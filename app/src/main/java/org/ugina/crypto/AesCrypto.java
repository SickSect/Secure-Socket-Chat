package org.ugina.crypto;

import org.ugina.crypto.exception.CryptoException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class AesCrypto {
    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH_BITS = 128;
    private static final int TAG_LENGTH_BYTES = TAG_LENGTH_BITS / 8;
    private static final String TRANSFORMATION_STRING = "AES/GCM/NoPadding";
    private static final SecureRandom RANDOM = new SecureRandom();

    public static String encrypt(String plainText, SecretKey secretKey) throws CryptoException {
        return Base64.getEncoder().encodeToString(encryptToByte(plainText, secretKey));
    }

    public static String encrypt(String plainText, SecretKey secretKey, byte[] aad)
            throws CryptoException {
        return Base64.getEncoder().encodeToString(encryptToByte(plainText, secretKey, aad));
    }

    public static byte[] encryptToByte(String plainText, SecretKey secretKey) throws CryptoException {
        return encryptToByte(plainText, secretKey, null);
    }

    public static byte[] encryptToByte(String plainText, SecretKey secretKey, byte[] aad)
            throws CryptoException {
        try {
            byte[] iv = new byte[IV_LENGTH];
            RANDOM.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION_STRING);
            GCMParameterSpec params = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, params);
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            byte[] payload = new byte[cipherText.length + IV_LENGTH];
            System.arraycopy(iv, 0, payload, 0, IV_LENGTH);
            System.arraycopy(cipherText, 0, payload, IV_LENGTH, cipherText.length);

            return payload;
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Encryption failed", e);
        }
    }

    public static String decrypt(String cipherText, SecretKey secretKey) throws CryptoException {
        return decrypt(cipherText, secretKey, null);
    }

    public static String decrypt(String cipherText, SecretKey secretKey, byte[] aad)
            throws CryptoException {
        byte[] payload = Base64.getDecoder().decode(cipherText);
        return decryptFromBytes(payload, secretKey, aad);
    }

    public static String decryptFromBytes(byte[] cipherTextBytes, SecretKey secretKey)
            throws CryptoException {
        return decryptFromBytes(cipherTextBytes, secretKey, null);
    }

    public static String decryptFromBytes(byte[] cipherTextBytes, SecretKey secretKey, byte[] aad)
            throws CryptoException {
        try {
            if (cipherTextBytes == null || cipherTextBytes.length < IV_LENGTH + TAG_LENGTH_BYTES) {
                throw new CryptoException("Ciphertext is too short", null);
            }
            byte[] iv = Arrays.copyOfRange(cipherTextBytes, 0, IV_LENGTH);
            byte[] payload = Arrays.copyOfRange(cipherTextBytes, IV_LENGTH, cipherTextBytes.length);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION_STRING);
            GCMParameterSpec params = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, params);
            if (aad != null) {
                cipher.updateAAD(aad);
            }

            return new String(cipher.doFinal(payload), StandardCharsets.UTF_8);
        } catch (CryptoException e) {
            throw e;
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new CryptoException("Decryption failed", e);
        }
    }
}
