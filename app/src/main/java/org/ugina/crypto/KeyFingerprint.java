package org.ugina.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.HexFormat;

/**
 * Stable, human-comparable fingerprint of an identity public key.
 *
 * <p>The fingerprint is a SHA-256 hash over a domain-separated, length-prefixed
 * encoding of the key. It is not secret: its only purpose is to let two users
 * compare the key they received through the server with the key the other side
 * actually owns.</p>
 */
public final class KeyFingerprint {

    private static final String LABEL = "secure-chat/v2/key-fingerprint";
    private static final int SHA_256_BYTES = 32;

    /** A trust decision should never be based on a very short prefix. */
    public static final int MIN_TRUST_PREFIX = 16;

    private KeyFingerprint() {
    }

    /**
     * Returns the full fingerprint as 64 lowercase hexadecimal characters.
     */
    public static String hex(PublicKey publicKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("publicKey is required");
        }
        byte[] encoded = publicKey.getEncoded();
        if (encoded == null || encoded.length == 0) {
            throw new IllegalArgumentException("publicKey has no encoded form");
        }
        MessageDigest digest = sha256();
        updateLengthPrefixed(digest, LABEL.getBytes(StandardCharsets.UTF_8));
        updateLengthPrefixed(digest, encoded);
        return HexFormat.of().formatHex(digest.digest());
    }

    /**
     * Removes spaces, colons, dashes and other separators and lowercases the
     * result. This lets users paste a fingerprint in any common format.
     */
    public static String normalize(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if ((c >= '0' && c <= '9')
                    || (c >= 'a' && c <= 'f')
                    || (c >= 'A' && c <= 'F')) {
                out.append(Character.toLowerCase(c));
            }
        }
        return out.toString();
    }

    /**
     * Groups a fingerprint for easier reading, for example
     * {@code "a1b2 c3d4 ..."}.
     */
    public static String format(String fingerprint) {
        String normalized = normalize(fingerprint);
        StringBuilder out = new StringBuilder(normalized.length() + normalized.length() / 4);
        for (int i = 0; i < normalized.length(); i++) {
            if (i > 0 && i % 4 == 0) {
                out.append(' ');
            }
            out.append(normalized.charAt(i));
        }
        return out.toString();
    }

    public static boolean isFingerprint(String value) {
        return normalize(value).length() == SHA_256_BYTES * 2;
    }

    /**
     * Checks that {@code prefix} is a sufficiently long prefix of the full
     * fingerprint. Sixteen hex characters (64 bits) is enough to make an
     * accidental match impractical, while still being easy to type.
     */
    public static boolean matchesPrefix(String fullFingerprint, String prefix) {
        String full = normalize(fullFingerprint);
        String candidate = normalize(prefix);
        return full.length() == SHA_256_BYTES * 2
                && candidate.length() >= MIN_TRUST_PREFIX
                && candidate.length() <= full.length()
                && full.startsWith(candidate);
    }

    public static String shortForm(String fingerprint) {
        String normalized = normalize(fingerprint);
        if (normalized.length() <= MIN_TRUST_PREFIX) {
            return normalized;
        }
        return normalized.substring(0, MIN_TRUST_PREFIX);
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static void updateLengthPrefixed(MessageDigest digest, byte[] value) {
        digest.update((byte) (value.length >>> 24));
        digest.update((byte) (value.length >>> 16));
        digest.update((byte) (value.length >>> 8));
        digest.update((byte) value.length);
        digest.update(value);
    }

}
