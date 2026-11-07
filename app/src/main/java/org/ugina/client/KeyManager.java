package org.ugina.client;

import org.ugina.crypto.RsaCrypto;
import org.ugina.crypto.keyStorage.FileBasedKeyStorage;
import org.ugina.crypto.keyStorage.KeyStorage;
import org.ugina.utils.UsernamePolicy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;

public class KeyManager {

    /**
     * The username becomes part of a filesystem path, so it must be validated
     * before use. This also rejects {@code ..} path traversal attempts.
     */
    private Path pathFor(String username) {
        if (!UsernamePolicy.isValid(username)) {
            throw new IllegalArgumentException("Invalid username");
        }
        return Path.of(
                System.getProperty("user.home"),
                ".secure-chat",
                username + ".key"
        );
    }

    private KeyStorage storageFor(String username) {
        return new FileBasedKeyStorage(pathFor(username));
    }

    /**
     * Creates a new RSA pair and stores it locally. Used during registration.
     *
     * @throws IllegalStateException if keys already exist for this username
     */
    public KeyPair createAndStore(String username, char[] password) throws Exception {
        KeyStorage storage = storageFor(username);
        if (storage.exists()) {
            throw new IllegalStateException(
                    "Keys for '" + username + "' already exist on this device");
        }
        KeyPair keyPair = RsaCrypto.generateKeyPair();
        storage.save(keyPair, password);
        return keyPair;
    }

    /**
     * Loads the existing RSA pair. Used during login.
     *
     * @throws IllegalStateException if no keys exist on this device
     */
    public KeyPair load(String username, char[] password) throws Exception {
        KeyStorage storage = storageFor(username);
        if (!storage.exists()) {
            throw new IllegalStateException(
                    "No keys for '" + username + "' on this device. Register first.");
        }
        return storage.load(password);
    }

    /**
     * Stores an existing RSA pair, overwriting any current local key file.
     * Used for identity-key rotation and for rolling back a rotation whose
     * server-side update failed (the device and the key directory must never
     * disagree).
     */
    public void store(String username, KeyPair keyPair, char[] password) throws Exception {
        if (keyPair == null) {
            throw new IllegalArgumentException("keyPair is required");
        }
        storageFor(username).save(keyPair, password);
    }

    /**
     * Removes a local key file, for example when the server rejected the
     * registration after the key had already been written.
     */
    public void delete(String username) {
        try {
            Files.deleteIfExists(pathFor(username));
        } catch (Exception ignored) {
            // best effort: the key is unusable anyway if registration failed
        }
    }
}
