package org.ugina;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.ugina.crypto.exception.CryptoException;
import org.ugina.crypto.HybridCrypto;
import org.ugina.crypto.RsaCrypto;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class HybridCryptoTest {
    private KeyPair keyPair;
    private KeyPair keyPairOpt;
    {
        try {
            keyPair = RsaCrypto.generateKeyPair();
        }catch (CryptoException e) {
            throw new RuntimeException(e);
        }
    }
    {
        try {
            keyPairOpt = RsaCrypto.generateKeyPair();
        }catch (CryptoException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testEncryptDecrypt() throws CryptoException {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        String plainText = "Hello World! Привет мир!";

        String encrypted = HybridCrypto.encrypt(plainText, publicKey);
        String decrypted = HybridCrypto.decrypt(encrypted, privateKey);
        Assert.assertEquals(decrypted, plainText);
    }

    @Test
    public void testEncryptDecryptLongMsg() throws CryptoException {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        String longText = "x".repeat(10_000);

        String encrypted = HybridCrypto.encrypt(longText, publicKey);
        String decrypted = HybridCrypto.decrypt(encrypted, privateKey);
        Assert.assertEquals(decrypted, longText);
    }

    @Test
    public void testEncryptDecryptKeyDifCipher() throws CryptoException {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        String plainText = "Hello World! Привет мир!";

        String encrypted1 = HybridCrypto.encrypt(plainText, publicKey);
        String decrypted1 = HybridCrypto.decrypt(encrypted1, privateKey);

        String encrypted2 = HybridCrypto.encrypt(plainText, publicKey);
        String decrypted2 = HybridCrypto.decrypt(encrypted2, privateKey);

        Assert.assertNotEquals(encrypted1, encrypted2);
        Assert.assertEquals(decrypted1, plainText);
        Assert.assertEquals(decrypted2, plainText);
    }

    @Test(expectedExceptions = CryptoException.class)
    public void testEncryptDecryptErrorDecrypt() throws CryptoException {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKeyOpt = keyPairOpt.getPrivate();
        String plainText = "Hello World! Привет мир!";

        String encrypted = HybridCrypto.encrypt(plainText, publicKey);
        String decrypted = HybridCrypto.decrypt(encrypted, privateKeyOpt);
    }
}
