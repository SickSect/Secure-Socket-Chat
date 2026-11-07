package org.ugina.crypto;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * A safety number is a deterministic value derived from both users' identity
 * public keys. Both sides compute the same number regardless of who starts the
 * conversation, so they can compare it over a separate channel (in person, a
 * phone call, a signed message, etc.).
 *
 * <p>If a malicious server substitutes one of the keys, the two safety numbers
 * will not match. This is the same idea as Signal's safety numbers, simplified
 * for a learning project.</p>
 *
 * <p>The number is <b>not</b> a secret and does not replace the handshake. It
 * only helps humans detect a lying key directory.</p>
 */
public final class SafetyNumber {

    private static final String LABEL = "secure-chat/v2/safety-number";
    private static final int GROUPS = 12;
    private static final int DIGITS_PER_GROUP = 5;
    private static final int TOTAL_DIGITS = GROUPS * DIGITS_PER_GROUP;

    private SafetyNumber() {
    }

    /**
     * Computes the same safety number from either side of a conversation.
     *
     * @throws IllegalArgumentException if a username or key is missing
     */
    public static String of(String userA, PublicKey keyA, String userB, PublicKey keyB) {
        if (userA == null || userA.isBlank() || userB == null || userB.isBlank()) {
            throw new IllegalArgumentException("usernames are required");
        }
        if (keyA == null || keyB == null) {
            throw new IllegalArgumentException("public keys are required");
        }

        byte[] keyABytes = encoded(keyA);
        byte[] keyBBytes = encoded(keyB);

        // Canonical ordering makes the result independent of who calls first.
        int order = userA.compareTo(userB);
        if (order == 0) {
            order = Arrays.compareUnsigned(keyABytes, keyBBytes);
        }

        MessageDigest digest = sha256();
        updateLengthPrefixed(digest, LABEL.getBytes(StandardCharsets.UTF_8));
        if (order <= 0) {
            updatePair(digest, userA, keyABytes);
            updatePair(digest, userB, keyBBytes);
        } else {
            updatePair(digest, userB, keyBBytes);
            updatePair(digest, userA, keyABytes);
        }
        return format(digest.digest());
    }

    private static String format(byte[] digest) {
        String decimal = new BigInteger(1, digest).toString();
        if (decimal.length() < TOTAL_DIGITS) {
            decimal = "0".repeat(TOTAL_DIGITS - decimal.length()) + decimal;
        } else if (decimal.length() > TOTAL_DIGITS) {
            decimal = decimal.substring(0, TOTAL_DIGITS);
        }

        StringBuilder out = new StringBuilder(TOTAL_DIGITS + GROUPS - 1);
        for (int group = 0; group < GROUPS; group++) {
            if (group > 0) {
                out.append(' ');
            }
            int start = group * DIGITS_PER_GROUP;
            out.append(decimal, start, start + DIGITS_PER_GROUP);
        }
        return out.toString();
    }

    private static void updatePair(MessageDigest digest, String username, byte[] key) {
        updateLengthPrefixed(digest, username.getBytes(StandardCharsets.UTF_8));
        updateLengthPrefixed(digest, key);
    }

    private static byte[] encoded(PublicKey key) {
        byte[] encoded = key.getEncoded();
        if (encoded == null || encoded.length == 0) {
            throw new IllegalArgumentException("public key has no encoded form");
        }
        return encoded;
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
