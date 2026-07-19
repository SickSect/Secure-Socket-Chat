package org.ugina.client;

import org.ugina.protocol.ErrorCode;

/**
 * Result of a JOIN attempt: either success, or failure with the server's error code.
 */
public record JoinOutcome(boolean success, ErrorCode errorCode) {

    public static JoinOutcome ok() {
        return new JoinOutcome(true, null);
    }

    public static JoinOutcome error(ErrorCode code) {
        return new JoinOutcome(false, code);
    }
}