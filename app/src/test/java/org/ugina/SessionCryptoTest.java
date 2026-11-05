package org.ugina;

import org.testng.annotations.Test;
import org.ugina.crypto.EcdhCrypto;
import org.ugina.crypto.SessionCrypto;
import org.ugina.crypto.exception.CryptoException;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Base64;

import static org.testng.Assert.*;

public class SessionCryptoTest {

    private record Handshake(
            SessionCrypto.DerivedKeys alice,
            SessionCrypto.DerivedKeys bob,
            byte[] aliceEphemeral,
            byte[] bobEphemeral
    ) {
    }

    private Handshake deriveBothSides(String aliceName, String bobName) throws Exception {
        KeyPair aliceKeyPair = EcdhCrypto.generateKeyPair();
        KeyPair bobKeyPair = EcdhCrypto.generateKeyPair();
        byte[] alicePub = aliceKeyPair.getPublic().getEncoded();
        byte[] bobPub = bobKeyPair.getPublic().getEncoded();

        byte[] aliceSecret = EcdhCrypto.computeSharedSecret(
                aliceKeyPair.getPrivate(), bobKeyPair.getPublic());
        byte[] bobSecret = EcdhCrypto.computeSharedSecret(
                bobKeyPair.getPrivate(), aliceKeyPair.getPublic());

        return new Handshake(
                SessionCrypto.derive(aliceSecret, aliceName, bobName, alicePub, bobPub),
                SessionCrypto.derive(bobSecret, aliceName, bobName, alicePub, bobPub),
                alicePub,
                bobPub);
    }

    @Test
    public void bothSidesDeriveTheSameDirectionalKeys() throws Exception {
        Handshake h = deriveBothSides("alice", "bob");

        assertEquals(h.alice().initiatorToResponder().getEncoded(),
                h.bob().initiatorToResponder().getEncoded());
        assertEquals(h.alice().responderToInitiator().getEncoded(),
                h.bob().responderToInitiator().getEncoded());
        assertEquals(h.alice().initiatorConfirm(), h.bob().initiatorConfirm());
        assertEquals(h.alice().responderConfirm(), h.bob().responderConfirm());
        assertEquals(h.alice().transcriptHash(), h.bob().transcriptHash());

        assertFalse(Arrays.equals(
                h.alice().initiatorToResponder().getEncoded(),
                h.alice().responderToInitiator().getEncoded()),
                "directions must use different keys");
    }

    @Test
    public void transcriptBindsBothEphemeralKeys() throws Exception {
        Handshake h = deriveBothSides("alice", "bob");

        SessionCrypto.DerivedKeys swapped = SessionCrypto.derive(
                h.alice().initiatorToResponder().getEncoded(),
                "alice", "bob", h.bobEphemeral(), h.aliceEphemeral());

        assertFalse(Arrays.equals(
                h.alice().transcriptHash(), swapped.transcriptHash()),
                "swapping ephemeral keys must change the transcript");
    }

    @Test
    public void transcriptBindsUsernames() throws Exception {
        Handshake h = deriveBothSides("alice", "bob");
        SessionCrypto.DerivedKeys other = SessionCrypto.derive(
                h.alice().initiatorToResponder().getEncoded(),
                "mallory", "bob", h.aliceEphemeral(), h.bobEphemeral());

        assertFalse(Arrays.equals(
                h.alice().transcriptHash(), other.transcriptHash()),
                "changing an identity must change the transcript");
    }

    @Test
    public void encryptDecryptRoundTrip() throws Exception {
        Handshake h = deriveBothSides("alice", "bob");
        String cipherText = SessionCrypto.encrypt(
                "hello", h.alice().initiatorToResponder(), "alice", "bob", 0);

        String plainText = SessionCrypto.decrypt(
                cipherText, h.bob().initiatorToResponder(), "alice", "bob", 0);
        assertEquals(plainText, "hello");
    }

    @Test(expectedExceptions = CryptoException.class)
    public void replayWithOldSequenceIsRejected() throws Exception {
        Handshake h = deriveBothSides("alice", "bob");
        String cipherText = SessionCrypto.encrypt(
                "hello", h.alice().initiatorToResponder(), "alice", "bob", 5);

        SessionCrypto.decrypt(
                cipherText, h.bob().initiatorToResponder(), "alice", "bob", 6);
    }

    @Test(expectedExceptions = CryptoException.class)
    public void wrongSenderIsRejectedByAad() throws Exception {
        Handshake h = deriveBothSides("alice", "bob");
        String cipherText = SessionCrypto.encrypt(
                "hello", h.alice().initiatorToResponder(), "alice", "bob", 0);

        SessionCrypto.decrypt(
                cipherText, h.bob().initiatorToResponder(), "mallory", "bob", 0);
    }

    @Test(expectedExceptions = CryptoException.class)
    public void tamperedCiphertextIsRejected() throws Exception {
        Handshake h = deriveBothSides("alice", "bob");
        String cipherText = SessionCrypto.encrypt(
                "hello", h.alice().initiatorToResponder(), "alice", "bob", 0);

        byte[] payload = Base64.getDecoder().decode(cipherText);
        payload[payload.length - 1] ^= 0x01;
        String tampered = Base64.getEncoder().encodeToString(payload);

        SessionCrypto.decrypt(
                tampered, h.bob().initiatorToResponder(), "alice", "bob", 0);
    }

    @Test(expectedExceptions = CryptoException.class)
    public void wrongDirectionKeyIsRejected() throws Exception {
        Handshake h = deriveBothSides("alice", "bob");
        String cipherText = SessionCrypto.encrypt(
                "hello", h.alice().initiatorToResponder(), "alice", "bob", 0);

        SessionCrypto.decrypt(
                cipherText, h.bob().responderToInitiator(), "alice", "bob", 0);
    }

    @Test
    public void signingPayloadChangesWithRoleAndPeer() {
        byte[] ephemeral = "ephemeral".getBytes(StandardCharsets.UTF_8);
        byte[] init = SessionCrypto.signingPayload("init", "alice", "bob", ephemeral);
        byte[] ack = SessionCrypto.signingPayload("ack", "alice", "bob", ephemeral);
        byte[] otherPeer = SessionCrypto.signingPayload("init", "alice", "carol", ephemeral);

        assertFalse(Arrays.equals(init, ack));
        assertFalse(Arrays.equals(init, otherPeer));
    }
}
