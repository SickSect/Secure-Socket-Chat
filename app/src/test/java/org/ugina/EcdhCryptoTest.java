package org.ugina;

import org.testng.annotations.Test;
import org.ugina.crypto.EcdhCrypto;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;

import static org.testng.Assert.*;

public class EcdhCryptoTest {
    @Test
    public void testGenerateKeyPair() throws Exception {
        KeyPair pair = EcdhCrypto.generateKeyPair();
        assertNotNull(pair.getPublic());
        assertNotNull(pair.getPrivate());
        assertEquals(pair.getPublic().getAlgorithm(), "EC");
    }

    @Test
    public void testSharedSecretMatches() throws Exception {
        // Главный тест ECDH: оба получают одинаковый секрет
        KeyPair alice = EcdhCrypto.generateKeyPair();
        KeyPair bob = EcdhCrypto.generateKeyPair();

        byte[] aliceSecret = EcdhCrypto.computeSharedSecret(
                alice.getPrivate(), bob.getPublic());
        byte[] bobSecret = EcdhCrypto.computeSharedSecret(
                bob.getPrivate(), alice.getPublic());

        assertEquals(aliceSecret, bobSecret);
        assertEquals(aliceSecret.length, 32);  // P-256 даёт 32 байта
    }

    @Test
    public void testDifferentPairsGiveDifferentSecrets() throws Exception {
        // Третья сторона с другой парой получает другой секрет
        KeyPair alice = EcdhCrypto.generateKeyPair();
        KeyPair bob = EcdhCrypto.generateKeyPair();
        KeyPair mallory = EcdhCrypto.generateKeyPair();

        byte[] aliceBobSecret = EcdhCrypto.computeSharedSecret(
                alice.getPrivate(), bob.getPublic());
        byte[] aliceMallorySecret = EcdhCrypto.computeSharedSecret(
                alice.getPrivate(), mallory.getPublic());

        assertFalse(Arrays.equals(aliceBobSecret, aliceMallorySecret));
    }

    @Test
    public void testKeySerialization() throws Exception {
        KeyPair pair = EcdhCrypto.generateKeyPair();

        String base64 = EcdhCrypto.publicKeyToBase64(pair.getPublic());
        PublicKey restored = EcdhCrypto.publicKeyFromBase64(base64);

        // После сериализации-десериализации ECDH всё ещё работает
        KeyPair other = EcdhCrypto.generateKeyPair();
        byte[] secretOriginal = EcdhCrypto.computeSharedSecret(
                other.getPrivate(), pair.getPublic());
        byte[] secretRestored = EcdhCrypto.computeSharedSecret(
                other.getPrivate(), restored);

        assertEquals(secretOriginal, secretRestored);
    }

    @Test
    public void testEphemeralPairsAreUnique() throws Exception {
        // Эфемерные пары должны быть РАЗНЫЕ каждый раз
        KeyPair pair1 = EcdhCrypto.generateKeyPair();
        KeyPair pair2 = EcdhCrypto.generateKeyPair();

        assertNotEquals(pair1.getPublic(), pair2.getPublic());
        assertNotEquals(pair1.getPrivate(), pair2.getPrivate());
    }
}
