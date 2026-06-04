package org.ugina;

import org.testng.annotations.Test;
import org.ugina.crypto.AesCrypto;
import org.ugina.crypto.exception.CryptoException;
import org.ugina.crypto.KeyLoader;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;

import static org.testng.Assert.*;

public class KeyLoaderTest {

    @Test
    public void loadAESKey() throws Exception {
        SecretKey key = KeyLoader.getSecretKey();
        assertNotNull(key);
    }

    @Test
    public void loadKeyLengthAndAlg() throws GeneralSecurityException {
        SecretKey key = KeyLoader.getSecretKey();
        assertEquals(key.getEncoded().length, 32);
        assertEquals(key.getAlgorithm(), "AES");
    }

    @Test
    public void loadAndUseKey() throws GeneralSecurityException, CryptoException {
        SecretKey key = KeyLoader.getSecretKey();
        assertNotNull(key);
        String plainText = "Hello World! Привет мир!";
        String result = AesCrypto.encrypt(plainText, key);
        assertNotEquals(result, plainText);
    }

}
