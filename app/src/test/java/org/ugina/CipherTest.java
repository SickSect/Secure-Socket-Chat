package org.ugina;

import org.ugina.crypto.Crypto;
import org.testng.annotations.Test;
import org.ugina.crypto.CryptoException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

import static org.testng.Assert.*;

public class CipherTest {
    private static final String TEST_KEY_BASE64 = "QAgkeGknd48YnaPKULHclbgWSEa4/Uj2Ox7g/BnsLWg=";


    private SecretKey loadSecretKey(String base64EncodedKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64EncodedKey);
        return new SecretKeySpec(keyBytes, "AES");
    }

    @Test
    public void testEncrypt() throws Exception {
        SecretKey secretKey = loadSecretKey(TEST_KEY_BASE64);

        String plainText = "Hello World! Привет мир!";

        String result = Crypto.encrypt(plainText, secretKey);
        System.out.println("RESULT: " + result);
        assertNotEquals(result, plainText);
    }

    @Test
    public void testDecrypt() throws Exception {
        SecretKey key = loadSecretKey(TEST_KEY_BASE64);
        String plainText = "Hello World! Привет мир!";

        String encrypted = Crypto.encrypt(plainText, key);
        String decrypted = Crypto.decrypt(encrypted, key);

        assertEquals(decrypted, plainText);
    }

    @Test
    public void testChangingIV() throws Exception {
        SecretKey secretKey = loadSecretKey(TEST_KEY_BASE64);
        String plainText = "Hello World! Привет мир!";

        String encrypted_a = Crypto.encrypt(plainText, secretKey);
        String encrypted_b = Crypto.encrypt(plainText, secretKey);
        System.out.println("encrypted_a: " + encrypted_a);
        System.out.println("encrypted_b: " + encrypted_b);
        String decrypted_a = Crypto.decrypt(encrypted_a, secretKey);
        System.out.println("decrypted_a: " + decrypted_a);
        String decrypted_b = Crypto.decrypt(encrypted_b, secretKey);
        System.out.println("decrypted_b: " + decrypted_b);
        assertNotEquals(encrypted_a, encrypted_b);
    }

    @Test(expectedExceptions = CryptoException.class)
    public void testEncryptAndAttack() throws Exception {
        SecretKey secretKey = loadSecretKey(TEST_KEY_BASE64);
        String plainText = "Hello World! Привет мир!";

        String encrypted = Crypto.encrypt(plainText, secretKey);
        byte[] encryptBytes = encrypted.getBytes();
        encryptBytes[20] ^= 1;
        String tampered = Base64.getEncoder().encodeToString(encryptBytes);
        String encryptTempered = Crypto.decrypt(tampered, secretKey);
    }
}
