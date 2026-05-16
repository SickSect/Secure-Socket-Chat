package org.ugina.protocol;

public enum ErrorCode {
    INVALID_NAME,
    NAME_TAKEN,
    INVALID_PUBLIC_KEY,   // ← новое
    RECIPIENT_OFFLINE,
    EXPIRED,              // ← новое
    REPLAY,               // ← новое
    DECRYPTION_FAILED,
    INVALID_FORMAT,
    INTERNAL_ERROR
}
