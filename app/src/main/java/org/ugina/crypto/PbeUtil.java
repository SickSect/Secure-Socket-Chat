package org.ugina.crypto;

import org.ugina.crypto.exception.CryptoException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class PbeUtil {

    /**
     * Versioned container. New files start with this magic, which lets us
     * raise the PBKDF2 work factor later without breaking existing key files.
     * Legacy files (no magic) are still readable with the old parameters.
     */
    private static final byte[] MAGIC_V2 = {'S', 'C', 'K', '1'};
    private static final int V2_ITERATIONS = 600_000;   // OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
    private static final int V1_ITERATIONS = 100_000;   // legacy files

    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int KEY_LENGTH_BITS = 256;
    private static final int TAG_LENGTH_BITS = 128;
    private static final int TAG_LENGTH_BYTES = TAG_LENGTH_BITS / 8;
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Encrypt data with a password-derived key.
     *
     * @return {@code MAGIC || salt || iv || ciphertext+tag}
     */
    public static byte[] encrypt(byte[] data, char[] password) throws Exception {
        byte[] salt = new byte[SALT_LENGTH];
        RANDOM.nextBytes(salt);
        byte[] iv = new byte[IV_LENGTH];
        RANDOM.nextBytes(iv);

        SecretKey aesKey = deriveKeyFromPassword(password, salt, V2_ITERATIONS);
        try {
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, parameterSpec);
            cipher.updateAAD(MAGIC_V2);

            byte[] cipherText = cipher.doFinal(data);
            byte[] finalPayload = new byte[
                    MAGIC_V2.length + SALT_LENGTH + IV_LENGTH + cipherText.length];
            int offset = 0;
            System.arraycopy(MAGIC_V2, 0, finalPayload, offset, MAGIC_V2.length);
            offset += MAGIC_V2.length;
            System.arraycopy(salt, 0, finalPayload, offset, salt.length);
            offset += salt.length;
            System.arraycopy(iv, 0, finalPayload, offset, iv.length);
            offset += iv.length;
            System.arraycopy(cipherText, 0, finalPayload, offset, cipherText.length);
            return finalPayload;
        } finally {
            wipe(aesKey);
        }
    }

    /**
     * Decrypt data produced by {@link #encrypt(byte[], char[])} or by the
     * legacy (v1) implementation.
     */
    public static byte[] decrypt(byte[] payload, char[] password) throws Exception {
        if (payload == null) {
            throw new CryptoException("Empty PBE payload", null);
        }

        boolean v2 = startsWithMagic(payload);
        int iterations = v2 ? V2_ITERATIONS : V1_ITERATIONS;
        int base = v2 ? MAGIC_V2.length : 0;
        int minLength = base + SALT_LENGTH + IV_LENGTH + TAG_LENGTH_BYTES;
        if (payload.length < minLength) {
            throw new CryptoException("PBE payload is too short", null);
        }

        byte[] salt = Arrays.copyOfRange(payload, base, base + SALT_LENGTH);
        byte[] iv = Arrays.copyOfRange(payload, base + SALT_LENGTH, base + SALT_LENGTH + IV_LENGTH);
        byte[] cipherText = Arrays.copyOfRange(
                payload, base + SALT_LENGTH + IV_LENGTH, payload.length);

        SecretKey aesKey = deriveKeyFromPassword(password, salt, iterations);
        try {
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmParameterSpec);
            if (v2) {
                cipher.updateAAD(MAGIC_V2);
            }
            return cipher.doFinal(cipherText);
        } catch (Exception e) {
            throw new CryptoException("PBE decryption failed (wrong password or corrupt data)", e);
        } finally {
            wipe(aesKey);
        }
    }

    private static SecretKey deriveKeyFromPassword(char[] password, byte[] salt, int iterations)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterations, KEY_LENGTH_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            byte[] keyBytes = factory.generateSecret(keySpec).getEncoded();
            try {
                return new SecretKeySpec(keyBytes, "AES");
            } finally {
                Arrays.fill(keyBytes, (byte) 0);
            }
        } finally {
            keySpec.clearPassword();
        }
    }

    private static boolean startsWithMagic(byte[] payload) {
        if (payload.length < MAGIC_V2.length) return false;
        for (int i = 0; i < MAGIC_V2.length; i++) {
            if (payload[i] != MAGIC_V2[i]) return false;
        }
        return true;
    }

    private static void wipe(SecretKey key) {
        if (key instanceof javax.security.auth.Destroyable destroyable) {
            try {
                destroyable.destroy();
            } catch (Exception ignored) {
                // best effort
            }
        }
    }
}
