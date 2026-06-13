package org.ugina.auth.exceptions;

public class InvalidTokenException extends Exception{
    public InvalidTokenException(String message) {
        super(message);
    }

    public InvalidTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
