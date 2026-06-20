package org.ugina.client;

import org.ugina.crypto.RsaCrypto;
import org.ugina.crypto.keyStorage.FileBasedKeyStorage;
import org.ugina.crypto.keyStorage.KeyStorage;

import java.nio.file.Path;
import java.security.KeyPair;

public class KeyManager {
    private KeyStorage storageFor(String username) {
        Path keyFile = Path.of(
                System.getProperty("user.home"),
                ".secure-chat",
                username + ".key"
        );
        return new FileBasedKeyStorage(keyFile);
    }

    /**
     * Создаёт новую RSA-пару и сохраняет её локально.
     * Используется при регистрации.
     *
     * @throws IllegalStateException если ключи уже существуют
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
     * Загружает существующую RSA-пару.
     * Используется при логине.
     *
     * @throws IllegalStateException если ключей нет на устройстве
     */
    public KeyPair load(String username, char[] password) throws Exception {
        KeyStorage storage = storageFor(username);
        if (!storage.exists()) {
            throw new IllegalStateException(
                    "No keys for '" + username + "' on this device. Register first.");
        }
        return storage.load(password);
    }
}
