package org.ugina;

import org.testng.annotations.Test;
import org.ugina.crypto.CryptoException;
import org.ugina.crypto.RsaCrypto;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

public class RsaCryptoTest {

    private KeyPair keyPair;
    private KeyPair keyPairOpt;
    {
        try {
            keyPair = RsaCrypto.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    {
        try {
            keyPairOpt = RsaCrypto.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testEncrypt() throws Exception {
        PublicKey publicKey = keyPair.getPublic();
        String plainText = "Hello World! Привет мир!";

        byte[] encrypted1 = RsaCrypto.encrypt(plainText.getBytes(), publicKey);
        byte[] encrypted2 = RsaCrypto.encrypt(plainText.getBytes(), publicKey);

        System.out.println("ENCRYPTED 1: " + Base64.getEncoder().encodeToString(encrypted1));
        System.out.println("ENCRYPTED 2: " + Base64.getEncoder().encodeToString(encrypted2));

        assertNotEquals(
                Base64.getEncoder().encodeToString(encrypted1),
                Base64.getEncoder().encodeToString(encrypted2)
        );
    }

    @Test
    public void testDecrypt() throws Exception {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        String plainText = "Hello World! Привет мир!";

        byte[] encrypted1 = RsaCrypto.encrypt(plainText.getBytes(), publicKey);
        byte[] encrypted2 = RsaCrypto.encrypt(plainText.getBytes(), publicKey);

        byte[] decrypted1 = RsaCrypto.decrypt(encrypted1, privateKey);
        byte[] decrypted2 = RsaCrypto.decrypt(encrypted2, privateKey);

        String decrypted1String = new String(decrypted1, StandardCharsets.UTF_8);
        String decrypted2String = new String(decrypted2, StandardCharsets.UTF_8);

        System.out.println("DECRYPTED 1: " + decrypted1String);
        System.out.println("DECRYPTED 2: " + decrypted2String);

        assertEquals(
                decrypted1String,
                decrypted2String);
    }

    @Test
    public void testPublicKeyToBase64() throws Exception {
        PublicKey publicKey1 = keyPair.getPublic();
        String pubKey1 = RsaCrypto.publicKeyToBase64(publicKey1);
        PublicKey publicKey2 = RsaCrypto.publicKeyFromBase64(pubKey1);
        String pubKey2 = RsaCrypto.publicKeyToBase64(publicKey2);
        System.out.println("PUBLIC KEY 1: " + pubKey1);
        System.out.println("PUBLIC KEY 2: " + pubKey2);
        assertEquals(pubKey1, pubKey2);
    }

    @Test
    public void testPrivateKeyToBase64() throws Exception {
        PrivateKey privateKey1 = keyPair.getPrivate();
        String privKey1 = RsaCrypto.privateKeyToBase64(privateKey1);
        PrivateKey privateKey2 = RsaCrypto.privateKeyFromBase64(privKey1);
        String privKey2 = RsaCrypto.privateKeyToBase64(privateKey2);
        System.out.println("PRIVATE KEY 1: " + privKey1);
        System.out.println("PRIVATE KEY 2: " + privKey2);
        assertEquals(privKey1, privKey2);
    }

    @Test(expectedExceptions = CryptoException.class)
    public void errorWhileDecrypting() throws Exception {
        PublicKey publicKey1 = keyPair.getPublic();
        PrivateKey privateKey1 = keyPair.getPrivate();
        PrivateKey privateKey2 = keyPairOpt.getPrivate();
        String plainText = "Hello World! Привет мир!";

        byte[] encrypted = RsaCrypto.encrypt(plainText.getBytes(), publicKey1);

        byte[] decrypted1 = RsaCrypto.decrypt(encrypted, privateKey1);
        byte[] decrypted2 = RsaCrypto.decrypt(encrypted, privateKey2);
    }
}
