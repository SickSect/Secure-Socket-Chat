package org.ugina.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class Crypto {
    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH_BITS = 128;
    private static final String TRANSOFRMATION_STRING = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    public static String encrypt(String plainText, SecretKey secretKey) throws CryptoException {
        try {
            byte[] iv = new byte[IV_LENGTH];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance(TRANSOFRMATION_STRING);
            GCMParameterSpec params = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, params);
            byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            byte[] payload = new byte[cipherText.length + IV_LENGTH];
            System.arraycopy(iv, 0, payload, 0, IV_LENGTH);
            System.arraycopy(cipherText, 0, payload, IV_LENGTH, cipherText.length);

            return Base64.getEncoder().encodeToString(payload);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Encryption failed", e);
        }
    }

    public static String decrypt(String cipherText, SecretKey secretKey) throws CryptoException {
        try {
            byte[] cipherTextBytes = Base64.getDecoder().decode(cipherText);
            byte[] iv = Arrays.copyOfRange(cipherTextBytes, 0, IV_LENGTH);
            byte[] payload = Arrays.copyOfRange(cipherTextBytes, IV_LENGTH, cipherTextBytes.length);

            Cipher cipher = Cipher.getInstance(TRANSOFRMATION_STRING);
            GCMParameterSpec params = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, params);

            return new String(cipher.doFinal(payload), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new CryptoException("Decryption failed", e);
        }
    }
}
