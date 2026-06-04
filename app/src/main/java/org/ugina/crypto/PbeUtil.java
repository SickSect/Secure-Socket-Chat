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
    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int ITERATIONS = 100_000;
    private static final int KEY_LENGTH_BITS = 256;
    private static final int TAG_LENGTH_BITES = 128;
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";

    /**
     * Зашифровать данные паролем.
     *
     * @param data     данные для шифрования (например, сериализованный RSA-ключ)
     * @param password пароль пользователя как char[] (НЕ String! см. ниже)
     * @return байтовый массив формата [salt][iv][ciphertext+authTag]
     *
     * Почему char[] а не String для пароля:
     * String в Java неизменяемый — после использования остаётся в памяти
     * до GC, который может никогда не случиться. char[] можно явно
     * Arrays.fill(password, '\0') обнулить сразу после использования.
     * Это стандарт для работы с паролями.
     */
    public static byte[] encrypt(byte[] data, char[] password) throws Exception {
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        SecretKey aesKey = deriveKeyFromPassword(password, salt);
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH_BITES, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, parameterSpec);

        byte[] cipherText = cipher.doFinal(data);
        byte[] finalPayload = new byte[cipherText.length + IV_LENGTH + SALT_LENGTH];
        // salt - iv - text
        System.arraycopy(salt, 0, finalPayload, 0, salt.length);
        System.arraycopy(iv, 0, finalPayload, salt.length, iv.length);
        System.arraycopy(cipherText, 0, finalPayload, salt.length + iv.length, cipherText.length);
        return finalPayload;
    }


    /**
     * Расшифровать данные паролем.
     *
     * @param payload  то что вернул encrypt: [salt][iv][ciphertext+authTag]
     * @param password пароль пользователя
     * @return расшифрованные данные, идентичные оригинальному data в encrypt
     *
     * Если пароль неверный — auth tag GCM не совпадёт, бросится CryptoException.
     * Это и есть проверка пароля — нет отдельного шага "проверить пароль".
     */
    public static byte[] decrypt(byte[] payload, char[] password) throws Exception {
        try{
            int minLength = SALT_LENGTH + IV_LENGTH + (TAG_LENGTH_BITES / 8);
            if (payload.length < minLength) {
                throw new CryptoException("Payload too short! length = " + payload.length, null);
            }
            byte[] salt = Arrays.copyOfRange(payload, 0, SALT_LENGTH);
            byte[] iv = Arrays.copyOfRange(payload, SALT_LENGTH, IV_LENGTH + SALT_LENGTH);
            byte[] cipherText = Arrays.copyOfRange(payload, SALT_LENGTH + IV_LENGTH, payload.length);

            SecretKey aesKey = deriveKeyFromPassword(password, salt);
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BITES, iv);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmParameterSpec);
            return cipher.doFinal(cipherText);
        }catch (Exception e) {
            throw new CryptoException("PBE decryption failed (wrong password?)", e);
        }
    }


    private static SecretKey deriveKeyFromPassword(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec keySpec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH_BITS);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        byte[] keyBytes = factory.generateSecret(keySpec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }
}