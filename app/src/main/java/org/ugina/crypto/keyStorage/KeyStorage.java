package org.ugina.crypto.keyStorage;

import org.ugina.crypto.exception.KeyStorageException;

import java.security.KeyPair;

public interface KeyStorage {
    boolean exists();
    void save(KeyPair keyPair, char[] password) throws Exception;
    KeyPair load(char[] password) throws KeyStorageException ;
}
