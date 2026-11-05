package org.ugina.server;

import org.ugina.protocol.ClientMessage;
import org.ugina.protocol.ErrorCode;
import org.ugina.utils.UsernamePolicy;

import java.util.Base64;

/**
 * Stateless validation for client-originated messages. Every check here is
 * about refusing malformed or abusive input before it reaches the room.
 */
public final class ServerHandlerService {

    /** Maximum 30 seconds of clock skew for the client-supplied timestamp. */
    private static final long MAX_CLOCK_SKEW_MS = 30_000;

    private static final int NONCE_BYTES = 16;
    private static final int MAX_NONCE_BASE64 = 64;
    private static final int MAX_E2E_PAYLOAD_CHARS = 96 * 1024;
    private static final int MAX_EPHEMERAL_KEY_CHARS = 2 * 1024;
    private static final int MAX_SIGNATURE_CHARS = 2 * 1024;
    private static final int MAX_CONFIRMATION_CHARS = 512;

    private ServerHandlerService() {
    }

    public static boolean isValidRecipient(String name) {
        return UsernamePolicy.isValid(name);
    }

    public static ErrorCode validateSendMessage(ClientMessage msg, ChatRoom room, String sender) {
        if (msg == null || sender == null) {
            return ErrorCode.INVALID_FORMAT;
        }
        if (!UsernamePolicy.isValid(msg.toClientName)) {
            return ErrorCode.INVALID_FORMAT;
        }
        if (msg.timestamp == null) {
            return ErrorCode.INVALID_FORMAT;
        }
        if (msg.nonce == null || msg.nonce.length() > MAX_NONCE_BASE64) {
            return ErrorCode.INVALID_FORMAT;
        }
        byte[] nonceBytes;
        try {
            nonceBytes = Base64.getDecoder().decode(msg.nonce);
        } catch (IllegalArgumentException e) {
            return ErrorCode.INVALID_FORMAT;
        }
        if (nonceBytes.length != NONCE_BYTES) {
            return ErrorCode.INVALID_FORMAT;
        }
        if (msg.e2ePayload == null
                || msg.e2ePayload.isEmpty()
                || msg.e2ePayload.length() > MAX_E2E_PAYLOAD_CHARS) {
            return ErrorCode.INVALID_FORMAT;
        }

        long now = System.currentTimeMillis();
        if (Math.abs(now - msg.timestamp) > MAX_CLOCK_SKEW_MS) {
            return ErrorCode.EXPIRED;
        }
        if (!room.checkAndAddNonce(sender, msg.nonce)) {
            return ErrorCode.REPLAY;
        }
        return null;
    }

    public static boolean isValidHandshake(ClientMessage msg, boolean requireConfirmation) {
        if (msg == null || !UsernamePolicy.isValid(msg.toClientName)) {
            return false;
        }
        if (msg.ephemeralPublicKey == null
                || msg.ephemeralPublicKey.isEmpty()
                || msg.ephemeralPublicKey.length() > MAX_EPHEMERAL_KEY_CHARS) {
            return false;
        }
        if (msg.signature == null
                || msg.signature.isEmpty()
                || msg.signature.length() > MAX_SIGNATURE_CHARS) {
            return false;
        }
        if (requireConfirmation) {
            return msg.confirmation != null
                    && !msg.confirmation.isEmpty()
                    && msg.confirmation.length() <= MAX_CONFIRMATION_CHARS;
        }
        return true;
    }

    public static boolean isValidConfirmation(ClientMessage msg) {
        return msg != null
                && UsernamePolicy.isValid(msg.toClientName)
                && msg.confirmation != null
                && !msg.confirmation.isEmpty()
                && msg.confirmation.length() <= MAX_CONFIRMATION_CHARS;
    }
}
