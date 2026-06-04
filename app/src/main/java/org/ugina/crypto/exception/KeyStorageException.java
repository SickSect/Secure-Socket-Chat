package org.ugina.crypto.exception;

public class KeyStorageException extends RuntimeException {
    public KeyStorageException(String message) {
        super(message);
    }

    public KeyStorageException(String message, Throwable cause) {
        super(message, cause);
    }
}
