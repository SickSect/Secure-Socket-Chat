package org.ugina.client;

import org.ugina.crypto.KeyFingerprint;
import org.ugina.utils.UsernamePolicy;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.PublicKey;
import java.time.Instant;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Local trust-on-first-use (TOFU) store for peer identity keys.
 *
 * <p>The chat server hands out public keys. If the server is malicious or gets
 * compromised, it could return its own key for Bob and sit in the middle of the
 * conversation. This store remembers the first key seen for every username and
 * refuses to silently accept a different key later.</p>
 *
 * <p>First contact is still a trust decision: the first key is pinned
 * automatically. Users must compare a safety number out of band to detect a
 * key substitution that happened on that very first contact. A later change is
 * blocked until the user explicitly runs {@code /trust <user> <prefix>}.</p>
 */
public final class PeerTrustStore {

    private static final String HEADER = "# secure-chat known peer keys v1";
    private static final Set<PosixFilePermission> OWNER_ONLY =
            PosixFilePermissions.fromString("rw-------");

    public enum Verification {
        /** No key was pinned before; this key has just been pinned. */
        FIRST_CONTACT,
        /** The key matches the pinned fingerprint. */
        KNOWN
    }

    private record PinnedKey(String fingerprint, long firstSeenEpochSeconds) {
    }

    private record PendingKey(PublicKey key, String fingerprint) {
    }

    private final Path file;
    private final Map<String, PinnedKey> pins = new LinkedHashMap<>();
    private final Map<String, PendingKey> pending = new LinkedHashMap<>();
    /**
     * Usernames whose pin this process changed. Refresh logic never overwrites
     * them with an older value read from disk; every other entry is refreshed
     * from disk before it is written back, so concurrent clients sharing the
     * file cannot clobber each other's decisions.
     */
    private final Set<String> dirty = new HashSet<>();

    public PeerTrustStore(Path file) {
        if (file == null) {
            throw new IllegalArgumentException("file is required");
        }
        this.file = file.toAbsolutePath().normalize();
        load();
    }

    /**
     * Default location: {@code ~/.secure-chat/known-peers.tsv}.
     *
     * <p>The system property {@code secure.chat.trustStore} or the environment
     * variable {@code SECURE_CHAT_TRUSTSTORE} can override the path, which is
     * useful for tests and for running several isolated profiles.</p>
     */
    public static PeerTrustStore defaultStore() {
        String override = System.getProperty("secure.chat.trustStore");
        if (override == null || override.isBlank()) {
            override = System.getenv("SECURE_CHAT_TRUSTSTORE");
        }
        Path path = (override != null && !override.isBlank())
                ? Path.of(override)
                : Path.of(System.getProperty("user.home"), ".secure-chat", "known-peers.tsv");
        return new PeerTrustStore(path);
    }

    /**
     * Checks a server-provided key against the local pin.
     *
     * @return {@link Verification#FIRST_CONTACT} when the key was pinned now,
     *         {@link Verification#KNOWN} when it matches an existing pin
     * @throws PeerKeyMismatchException when a different key is offered; the
     *         candidate is kept for an explicit {@link #trustPending} call
     */
    public synchronized Verification verify(String username, PublicKey key)
            throws PeerKeyMismatchException {
        requireUsername(username);
        if (key == null) {
            throw new IllegalArgumentException("key is required");
        }

        String fingerprint = KeyFingerprint.hex(key);
        // Pick up pins written by other client processes before deciding.
        refreshFromDisk();
        PinnedKey pinned = pins.get(username);

        if (pinned == null) {
            pins.put(username, new PinnedKey(fingerprint, Instant.now().getEpochSecond()));
            dirty.add(username);
            try {
                save();
            } catch (RuntimeException e) {
                pins.remove(username);
                dirty.remove(username);
                throw e;
            }
            pending.remove(username);
            return Verification.FIRST_CONTACT;
        }

        if (pinned.fingerprint().equals(fingerprint)) {
            pending.remove(username);
            return Verification.KNOWN;
        }

        // Do not replace the pin. Keep the candidate only in memory so the
        // user can inspect its fingerprint and explicitly accept it.
        pending.put(username, new PendingKey(key, fingerprint));
        throw new PeerKeyMismatchException(username, pinned.fingerprint(), fingerprint);
    }

    /**
     * Accepts a previously rejected key after the user has verified its
     * fingerprint out of band.
     *
     * @param fingerprintPrefix at least 16 hex characters of the offered key's
     *                          fingerprint; spaces/colons are ignored
     * @return the newly trusted public key
     */
    public synchronized PublicKey trustPending(String username, String fingerprintPrefix) {
        requireUsername(username);
        PendingKey candidate = pending.get(username);
        if (candidate == null) {
            throw new IllegalStateException("No changed key is pending for '" + username
                    + "'. Request the key first (for example, try to send a message).");
        }
        if (!KeyFingerprint.matchesPrefix(candidate.fingerprint(), fingerprintPrefix)) {
            throw new IllegalArgumentException("Fingerprint prefix does not match the key offered for '"
                    + username + "'. Expected a prefix of "
                    + KeyFingerprint.format(candidate.fingerprint()) + ".");
        }

        boolean wasDirty = dirty.contains(username);
        PinnedKey previous = pins.put(username,
                new PinnedKey(candidate.fingerprint(), Instant.now().getEpochSecond()));
        dirty.add(username);
        try {
            save();
        } catch (RuntimeException e) {
            if (previous == null) {
                pins.remove(username);
                dirty.remove(username);
            } else {
                pins.put(username, previous);
                if (!wasDirty) {
                    dirty.remove(username);
                }
            }
            throw e;
        }
        pending.remove(username);
        return candidate.key();
    }

    public synchronized Optional<String> pinnedFingerprint(String username) {
        if (username == null) {
            return Optional.empty();
        }
        PinnedKey pinned = pins.get(username);
        return pinned == null ? Optional.empty() : Optional.of(pinned.fingerprint());
    }

    public synchronized Optional<String> pendingFingerprint(String username) {
        if (username == null) {
            return Optional.empty();
        }
        PendingKey candidate = pending.get(username);
        return candidate == null ? Optional.empty() : Optional.of(candidate.fingerprint());
    }

    public Path path() {
        return file;
    }

    private void load() {
        if (!Files.exists(file)) {
            return;
        }
        try {
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                ParsedPin parsed = parseLine(line);
                if (parsed == null) {
                    continue;
                }
                if (pins.putIfAbsent(parsed.username(), parsed.pin()) != null) {
                    throw new IllegalStateException("Duplicate peer key entry for '"
                            + parsed.username() + "' in " + file);
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read known peer keys from " + file, e);
        }
    }

    /**
     * Re-reads pins written by other processes. Entries this process has
     * changed itself ({@link #dirty}) keep their in-memory value; everything
     * else is refreshed, so a client that started earlier cannot write back a
     * stale pin and silently undo a decision made in the meantime.
     */
    private void refreshFromDisk() {
        if (!Files.exists(file)) {
            return;
        }
        try {
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                ParsedPin parsed = parseLine(line);
                if (parsed != null && !dirty.contains(parsed.username())) {
                    pins.put(parsed.username(), parsed.pin());
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read known peer keys from " + file, e);
        }
    }

    private record ParsedPin(String username, PinnedKey pin) {
    }

    private ParsedPin parseLine(String line) {
        String trimmed = line.trim();
        if (trimmed.isEmpty() || trimmed.startsWith("#")) {
            return null;
        }
        String[] fields = trimmed.split("\t", -1);
        if (fields.length != 3) {
            throw new IllegalStateException("Malformed line in " + file
                    + ": expected 3 tab-separated fields");
        }
        String username = fields[0];
        if (!UsernamePolicy.isValid(username)) {
            throw new IllegalStateException("Invalid username in " + file);
        }
        String fingerprint = KeyFingerprint.normalize(fields[1]);
        if (!KeyFingerprint.isFingerprint(fingerprint)) {
            throw new IllegalStateException("Invalid fingerprint in " + file);
        }
        long firstSeen;
        try {
            firstSeen = Long.parseLong(fields[2]);
        } catch (NumberFormatException e) {
            throw new IllegalStateException("Invalid timestamp in " + file, e);
        }
        return new ParsedPin(username, new PinnedKey(fingerprint, firstSeen));
    }

    private void save() {
        Path directory = file.getParent();
        if (directory == null) {
            throw new IllegalStateException("Cannot determine directory for " + file);
        }

        try {
            Files.createDirectories(directory);
            Path lockFile = directory.resolve(file.getFileName() + ".lock");
            // Several client processes may share this file (two chat windows
            // opened from the same desktop account). The lock serialises
            // writers; refreshFromDisk() keeps pins written by other processes.
            try (FileChannel lockChannel = FileChannel.open(lockFile,
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                 FileLock ignored = lockChannel.lock()) {
                refreshFromDisk();

                Path temp = Files.createTempFile(directory, "known-peers-", ".tmp");
                try {
                    StringBuilder out = new StringBuilder(HEADER).append('\n');
                    pins.entrySet().stream()
                            .sorted(Map.Entry.comparingByKey())
                            .forEach(entry -> out.append(entry.getKey())
                                    .append('\t')
                                    .append(entry.getValue().fingerprint())
                                    .append('\t')
                                    .append(entry.getValue().firstSeenEpochSeconds())
                                    .append('\n'));

                    Files.writeString(temp, out.toString(), StandardCharsets.UTF_8);
                    restrictPermissions(temp);
                    moveAtomically(temp, file);
                    restrictPermissions(file);
                    temp = null;
                } finally {
                    if (temp != null) {
                        try {
                            Files.deleteIfExists(temp);
                        } catch (IOException cleanupFailure) {
                            // best effort
                        }
                    }
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("Cannot save known peer keys to " + file, e);
        }
    }

    private static void requireUsername(String username) {
        if (!UsernamePolicy.isValid(username)) {
            throw new IllegalArgumentException("Invalid username");
        }
    }

    private static void moveAtomically(Path source, Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void restrictPermissions(Path path) {
        try {
            Files.setPosixFilePermissions(path, OWNER_ONLY);
        } catch (UnsupportedOperationException | IOException ignored) {
            // Windows and some filesystems do not expose POSIX permissions.
        }
    }
}
