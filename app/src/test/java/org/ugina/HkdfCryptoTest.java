package org.ugina;

import org.testng.annotations.Test;
import org.ugina.crypto.EcdhCrypto;
import org.ugina.crypto.HkdfCrypto;

import java.security.KeyPair;
import java.util.Arrays;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;

public class HkdfCryptoTest {
    @Test
    public void testRfc5869TestCase1() throws Exception {
        // Тест-вектор из RFC 5869 Appendix A.1 — основной для HkdfCrypto
        byte[] ikm = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = hexToBytes("000102030405060708090a0b0c");
        byte[] info = hexToBytes("f0f1f2f3f4f5f6f7f8f9");

        byte[] prk = HkdfCrypto.extract(ikm, salt);
        String expectedPrk = "077709362c2e32df0ddc3f0dc47bba63" +
                "90b6c73bb50f9c3122ec844ad7c2b3e5";
        assertEquals(bytesToHex(prk), expectedPrk);

        byte[] okm = HkdfCrypto.expand(prk, info, 42);
        String expectedOkm = "3cb25f25faacd57a90434f64d0362f2a" +
                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
                "34007208d5b887185865";
        assertEquals(bytesToHex(okm), expectedOkm);
    }

    @Test
    public void testDeriveSessionKey() throws Exception {
        // Реалистичный сценарий: из ECDH-секрета получаем session_key
        KeyPair alice = EcdhCrypto.generateKeyPair();
        KeyPair bob = EcdhCrypto.generateKeyPair();

        byte[] sharedSecret = EcdhCrypto.computeSharedSecret(
                alice.getPrivate(), bob.getPublic());

        byte[] sessionKey = HkdfCrypto.derive(sharedSecret, null, "secure-chat-session", 32);

        assertEquals(sessionKey.length, 32);
    }

    @Test
    public void testBothSidesGetSameKey() throws Exception {
        // Alice и Bob независимо выводят одинаковый session_key
        KeyPair alice = EcdhCrypto.generateKeyPair();
        KeyPair bob = EcdhCrypto.generateKeyPair();

        byte[] aliceSecret = EcdhCrypto.computeSharedSecret(
                alice.getPrivate(), bob.getPublic());
        byte[] bobSecret = EcdhCrypto.computeSharedSecret(
                bob.getPrivate(), alice.getPublic());

        byte[] aliceKey = HkdfCrypto.derive(aliceSecret, null, "session", 32);
        byte[] bobKey = HkdfCrypto.derive(bobSecret, null, "session", 32);

        assertEquals(aliceKey, bobKey);
    }

    @Test
    public void testDifferentInfoGivesDifferentKeys() throws Exception {
        // Главное свойство HkdfCrypto: разный info → разные ключи из одного секрета
        byte[] ikm = "shared-secret".getBytes();

        byte[] encKey = HkdfCrypto.derive(ikm, null, "encryption", 32);
        byte[] macKey = HkdfCrypto.derive(ikm, null, "mac", 32);

        assertFalse(Arrays.equals(encKey, macKey));
    }

    @Test
    public void testCustomLength() throws Exception {
        byte[] ikm = "secret".getBytes();

        byte[] short_key = HkdfCrypto.derive(ikm, null, "test", 16);  // 128 бит
        byte[] long_key = HkdfCrypto.derive(ikm, null, "test", 64);   // 512 бит

        assertEquals(short_key.length, 16);
        assertEquals(long_key.length, 64);

        // Короткий ключ — это префикс длинного (свойство HkdfCrypto)
        byte[] longPrefix = Arrays.copyOfRange(long_key, 0, 16);
        assertEquals(short_key, longPrefix);
    }

    // Вспомогательные методы для тестов

    private static byte[] hexToBytes(String hex) {
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}
