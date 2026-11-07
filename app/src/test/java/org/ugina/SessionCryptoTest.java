package org.ugina;

import org.testng.annotations.Test;
import org.ugina.crypto.EcdhCrypto;
import org.ugina.crypto.SessionCrypto;
import org.ugina.crypto.exception.CryptoException;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;

import static org.testng.Assert.*;

public class SessionCryptoTest {

    private record Handshake(
            SessionCrypto.DerivedKeys alice,
            SessionCrypto.DerivedKeys bob
    ) {
    }

    private Handshake deriveBoth(String initiator, String responder) throws Exception {
        KeyPair aliceKeyPair = EcdhCrypto.generateKeyPair();
        KeyPair bobKeyPair = EcdhCrypto.generateKeyPair();
        byte[] alicePub = aliceKeyPair.getPublic().getEncoded();
        byte[] bobPub = bobKeyPair.getPublic().getEncoded();

        byte[] aliceSecret = EcdhCrypto.computeSharedSecret(
                aliceKeyPair.getPrivate(), bobKeyPair.getPublic());
        byte[] bobSecret = EcdhCrypto.computeSharedSecret(
                bobKeyPair.getPrivate(), aliceKeyPair.getPublic());

        return new Handshake(
                SessionCrypto.derive(aliceSecret, initiator, responder, alicePub, bobPub),
                SessionCrypto.derive(bobSecret, initiator, responder, alicePub, bobPub));
    }

    // ─── handshake derivation ───

    @Test
    public void bothSidesDeriveIdenticalRootAndConfirmations() throws Exception {
        Handshake h = deriveBoth("alice", "bob");

        assertBytesEqual(h.alice().rootKey(), h.bob().rootKey());
        assertBytesEqual(h.alice().initiatorConfirm(), h.bob().initiatorConfirm());
        assertBytesEqual(h.alice().responderConfirm(), h.bob().responderConfirm());
        assertBytesEqual(h.alice().transcriptHash(), h.bob().transcriptHash());
        assertFalse(java.util.Arrays.equals(
                h.alice().initiatorConfirm(), h.alice().responderConfirm()),
                "the two confirmation tags must differ");
    }

    @Test
    public void differentSessionsDeriveDifferentRoots() throws Exception {
        Handshake first = deriveBoth("alice", "bob");
        Handshake second = deriveBoth("alice", "bob");

        assertFalse(java.util.Arrays.equals(first.alice().rootKey(), second.alice().rootKey()),
                "fresh handshakes must never reuse a root key");
    }

    @Test
    public void transcriptBindsBothIdentities() throws Exception {
        Handshake honest = deriveBoth("alice", "bob");
        Handshake swapped = deriveBoth("bob", "alice");

        assertFalse(java.util.Arrays.equals(
                        honest.alice().rootKey(), swapped.alice().rootKey()),
                "renaming the peers must change the derived root");
    }

    // ─── ratchet KDFs ───

    @Test
    public void kdfRkIsDeterministicAndDirectional() throws Exception {
        byte[] root = new byte[32];
        java.util.Arrays.fill(root, (byte) 7);
        byte[] dh = new byte[32];
        java.util.Arrays.fill(dh, (byte) 9);

        SessionCrypto.RatchetStep a = SessionCrypto.kdfRk(root, dh, "i2r");
        SessionCrypto.RatchetStep b = SessionCrypto.kdfRk(root, dh, "i2r");
        SessionCrypto.RatchetStep otherDirection = SessionCrypto.kdfRk(root, dh, "r2i");

        assertBytesEqual(a.rootKey(), b.rootKey());
        assertBytesEqual(a.chainKey(), b.chainKey());
        assertFalse(java.util.Arrays.equals(a.chainKey(), otherDirection.chainKey()),
                "the two directions must never share a chain key");
        assertFalse(java.util.Arrays.equals(a.rootKey(), root),
                "the root key must rotate on every ratchet step");
        assertFalse(java.util.Arrays.equals(a.rootKey(), a.chainKey()));
    }

    @Test
    public void kdfCkProducesFreshMessageKeys() throws Exception {
        byte[] chain = new byte[32];
        java.util.Arrays.fill(chain, (byte) 3);

        SessionCrypto.ChainStep first = SessionCrypto.kdfCk(chain);
        SessionCrypto.ChainStep second = SessionCrypto.kdfCk(first.nextChainKey());

        assertFalse(java.util.Arrays.equals(first.messageKey(), first.nextChainKey()));
        assertFalse(java.util.Arrays.equals(first.messageKey(), second.messageKey()),
                "every chain step must produce a different message key");
        assertFalse(java.util.Arrays.equals(first.nextChainKey(), second.nextChainKey()));
    }

    @Test(expectedExceptions = CryptoException.class)
    public void kdfRkRejectsMissingInput() throws Exception {
        SessionCrypto.kdfRk(null, new byte[32], "i2r");
    }

    // ─── message format ───

    @Test
    public void encryptDecryptRoundtrip() throws Exception {
        SessionCrypto.ChainStep step = SessionCrypto.kdfCk(new byte[32]);
        String payload = SessionCrypto.encrypt(
                "hello мир", secretKey(step.messageKey()), "alice", "bob", 0, 0, null);

        String plain = SessionCrypto.decrypt(payload, secretKey(step.messageKey()),
                "alice", "bob", 0, 0);
        assertEquals(plain, "hello мир");
    }

    @Test
    public void roundtripWithEmbeddedRatchetKey() throws Exception {
        KeyPair pair = EcdhCrypto.generateKeyPair();
        byte[] rawRatchetKey = EcdhCrypto.publicKeyToRaw(pair.getPublic());
        SessionCrypto.ChainStep step = SessionCrypto.kdfCk(new byte[32]);

        String payload = SessionCrypto.encrypt("hi", secretKey(step.messageKey()),
                "alice", "bob", 4, 2, rawRatchetKey);

        SessionCrypto.Header header = SessionCrypto.parseHeader(payload);
        assertTrue(header.hasNewRatchetKey());
        assertBytesEqual(header.ratchetPublicKey(), rawRatchetKey);
        assertEquals(header.sequence(), 4);
        assertEquals(header.chainIndex(), 2);

        String plain = SessionCrypto.decrypt(payload, secretKey(step.messageKey()),
                "alice", "bob", 4, 2);
        assertEquals(plain, "hi");
    }

    @Test
    public void decryptRejectsWrongSequenceOrChainIndex() throws Exception {
        SessionCrypto.ChainStep step = SessionCrypto.kdfCk(new byte[32]);
        String payload = SessionCrypto.encrypt("x", secretKey(step.messageKey()),
                "alice", "bob", 5, 3, null);

        try {
            SessionCrypto.decrypt(payload, secretKey(step.messageKey()),
                    "alice", "bob", 6, 3);
            fail("wrong sequence must be rejected");
        } catch (CryptoException expectedFailure) {
            // expected
        }
        try {
            SessionCrypto.decrypt(payload, secretKey(step.messageKey()),
                    "alice", "bob", 5, 4);
            fail("wrong chain index must be rejected");
        } catch (CryptoException expectedFailure) {
            // expected
        }
    }

    @Test
    public void decryptRejectsWrongKeyAndWrongIdentities() throws Exception {
        SessionCrypto.ChainStep step = SessionCrypto.kdfCk(new byte[32]);
        byte[] otherChain = new byte[32];
        otherChain[0] = 1; // genuinely different chain key
        SessionCrypto.ChainStep other = SessionCrypto.kdfCk(otherChain);
        String payload = SessionCrypto.encrypt("secret", secretKey(step.messageKey()),
                "alice", "bob", 0, 0, null);

        try {
            SessionCrypto.decrypt(payload, secretKey(other.messageKey()),
                    "alice", "bob", 0, 0);
            fail("wrong message key must be rejected");
        } catch (CryptoException expectedFailure) {
            // expected
        }
        try {
            SessionCrypto.decrypt(payload, secretKey(step.messageKey()),
                    "mallory", "bob", 0, 0);
            fail("rewritten sender identity must be rejected (AAD)");
        } catch (CryptoException expectedFailure) {
            // expected
        }
    }

    @Test
    public void tamperedPayloadIsRejected() throws Exception {
        SessionCrypto.ChainStep step = SessionCrypto.kdfCk(new byte[32]);
        String payload = SessionCrypto.encrypt("intact", secretKey(step.messageKey()),
                "alice", "bob", 0, 0, null);

        byte[] bytes = Base64.getDecoder().decode(payload);
        bytes[bytes.length - 1] ^= 0x01;
        String tampered = Base64.getEncoder().encodeToString(bytes);

        try {
            SessionCrypto.decrypt(tampered, secretKey(step.messageKey()),
                    "alice", "bob", 0, 0);
            fail("tampered ciphertext must be rejected");
        } catch (CryptoException expectedFailure) {
            // expected
        }
    }

    @Test
    public void parseHeaderRejectsUnknownFlagsAndBadVersion() throws Exception {
        SessionCrypto.ChainStep step = SessionCrypto.kdfCk(new byte[32]);
        String payload = SessionCrypto.encrypt("x", secretKey(step.messageKey()),
                "alice", "bob", 0, 0, null);

        byte[] bytes = Base64.getDecoder().decode(payload);
        bytes[1] = (byte) 0x7F; // unknown flag bits
        try {
            SessionCrypto.parseHeader(Base64.getEncoder().encodeToString(bytes));
            fail("unknown flags must be rejected");
        } catch (CryptoException expectedFailure) {
            // expected
        }

        bytes = Base64.getDecoder().decode(payload);
        bytes[0] = 2; // pretend to be a v2 payload
        try {
            SessionCrypto.parseHeader(Base64.getEncoder().encodeToString(bytes));
            fail("wrong version must be rejected");
        } catch (CryptoException expectedFailure) {
            // expected
        }
    }

    @Test(expectedExceptions = CryptoException.class)
    public void encryptRejectsMalformedRatchetKey() throws Exception {
        SessionCrypto.ChainStep step = SessionCrypto.kdfCk(new byte[32]);
        SessionCrypto.encrypt("x", secretKey(step.messageKey()),
                "alice", "bob", 0, 0, new byte[10]);
    }

    @Test
    public void signingPayloadBindsRoleAndIdentities() {
        byte[] key = "k".getBytes(StandardCharsets.UTF_8);
        byte[] init = SessionCrypto.signingPayload("init", "alice", "bob", key);
        byte[] ack = SessionCrypto.signingPayload("ack", "alice", "bob", key);
        byte[] otherPeer = SessionCrypto.signingPayload("init", "alice", "carol", key);

        assertFalse(java.util.Arrays.equals(init, ack));
        assertFalse(java.util.Arrays.equals(init, otherPeer));
    }

    private static javax.crypto.SecretKey secretKey(byte[] raw) {
        return new org.ugina.crypto.DestroyableSecretKey(raw.clone(), "AES");
    }

    private static void assertBytesEqual(byte[] actual, byte[] expected) {
        assertBytesEqual(actual, expected, "expected byte arrays to be equal");
    }

    private static void assertBytesEqual(byte[] actual, byte[] expected, String message) {
        assertTrue(java.util.Arrays.equals(actual, expected), message);
    }
}
