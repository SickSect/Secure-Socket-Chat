package org.ugina;

import org.testng.annotations.Test;
import org.ugina.crypto.RsaCrypto;
import org.ugina.crypto.RsaSignature;

import java.security.KeyPair;

import static org.testng.Assert.*;

public class RsaSignatureTest {
    @Test
    public void testSignAndVerify() throws Exception {
        KeyPair pair = RsaCrypto.generateKeyPair();
        byte[] data = "important message".getBytes();

        byte[] signature = RsaSignature.sign(data, pair.getPrivate());
        boolean valid = RsaSignature.verify(data, signature, pair.getPublic());

        assertTrue(valid);
    }

    @Test
    public void testVerifyFailsWithModifiedData() throws Exception {
        KeyPair pair = RsaCrypto.generateKeyPair();
        byte[] original = "hello".getBytes();
        byte[] modified = "hellp".getBytes();  // одна буква изменена

        byte[] signature = RsaSignature.sign(original, pair.getPrivate());
        boolean valid = RsaSignature.verify(modified, signature, pair.getPublic());

        assertFalse(valid);
    }

    @Test
    public void testVerifyFailsWithWrongKey() throws Exception {
        KeyPair pair1 = RsaCrypto.generateKeyPair();
        KeyPair pair2 = RsaCrypto.generateKeyPair();  // другая пара
        byte[] data = "message".getBytes();

        byte[] signature = RsaSignature.sign(data, pair1.getPrivate());
        boolean valid = RsaSignature.verify(data, signature, pair2.getPublic());

        assertFalse(valid);
    }

    @Test
    public void testSameDataGivesSameSignature() throws Exception {
        // RSA-подпись детерминированная (в отличие от шифрования).
        // Один и тот же ключ + те же данные → та же подпись.
        KeyPair pair = RsaCrypto.generateKeyPair();
        byte[] data = "test".getBytes();

        byte[] sig1 = RsaSignature.sign(data, pair.getPrivate());
        byte[] sig2 = RsaSignature.sign(data, pair.getPrivate());

        // SHA256withRSA по PKCS#1 v1.5 — детерминированный
        assertEquals(sig1, sig2);
    }
}
