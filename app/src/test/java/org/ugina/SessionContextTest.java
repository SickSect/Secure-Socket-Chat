package org.ugina;

import org.testng.annotations.Test;
import org.ugina.client.SessionContext;
import org.ugina.crypto.EcdhCrypto;
import org.ugina.crypto.SessionCrypto;

import java.security.KeyPair;
import java.util.Arrays;

import static org.testng.Assert.*;

public class SessionContextTest {

    private record Pair(SessionContext alice, SessionContext bob,
                        SessionCrypto.DerivedKeys aliceKeys,
                        SessionCrypto.DerivedKeys bobKeys) {
    }

    private Pair handshake() throws Exception {
        KeyPair aliceEphemeral = EcdhCrypto.generateKeyPair();
        KeyPair bobEphemeral = EcdhCrypto.generateKeyPair();
        byte[] alicePub = aliceEphemeral.getPublic().getEncoded();
        byte[] bobPub = bobEphemeral.getPublic().getEncoded();

        byte[] aliceSecret = EcdhCrypto.computeSharedSecret(
                aliceEphemeral.getPrivate(), bobEphemeral.getPublic());
        byte[] bobSecret = EcdhCrypto.computeSharedSecret(
                bobEphemeral.getPrivate(), aliceEphemeral.getPublic());

        SessionCrypto.DerivedKeys aliceKeys = SessionCrypto.derive(
                aliceSecret, "alice", "bob", alicePub, bobPub);
        SessionCrypto.DerivedKeys bobKeys = SessionCrypto.derive(
                bobSecret, "alice", "bob", alicePub, bobPub);

        SessionContext alice = new SessionContext(
                "alice", "bob", aliceEphemeral, SessionContext.Role.INITIATOR);
        SessionContext bob = new SessionContext(
                "bob", "alice", bobEphemeral, SessionContext.Role.RESPONDER);
        return new Pair(alice, bob, aliceKeys, bobKeys);
    }

    @Test
    public void handshakeRequiresKeyConfirmation() throws Exception {
        Pair p = handshake();

        byte[] responderConfirm = p.bob().completeAsResponder(p.bobKeys());
        assertFalse(p.bob().isReady(), "responder must wait for the initiator's confirmation");

        byte[] initiatorConfirm = p.alice().completeAsInitiator(p.aliceKeys(), responderConfirm);
        p.alice().markEstablished();
        assertTrue(p.alice().isReady());

        p.bob().confirmInitiator(initiatorConfirm);
        assertTrue(p.bob().isReady());
        assertTrue(p.alice().getHandshakeResult().isDone());
        assertTrue(p.bob().getHandshakeResult().isDone());
    }

    @Test(expectedExceptions = Exception.class)
    public void wrongConfirmationFailsHandshake() throws Exception {
        Pair p = handshake();
        p.alice().completeAsInitiator(p.aliceKeys(), new byte[32]);
    }

    @Test
    public void directionalKeysAreMirrored() throws Exception {
        Pair p = handshake();
        p.bob().completeAsResponder(p.bobKeys());
        p.alice().completeAsInitiator(p.aliceKeys(), p.aliceKeys().responderConfirm());

        assertEquals(p.alice().getSendKey().getEncoded(), p.bob().getReceiveKey().getEncoded());
        assertEquals(p.bob().getSendKey().getEncoded(), p.alice().getReceiveKey().getEncoded());
        assertFalse(Arrays.equals(
                p.alice().getSendKey().getEncoded(),
                p.alice().getReceiveKey().getEncoded()));
    }

    @Test
    public void messagesAreAuthenticatedAndSequenced() throws Exception {
        Pair p = handshake();
        p.bob().completeAsResponder(p.bobKeys());
        p.alice().completeAsInitiator(p.aliceKeys(), p.aliceKeys().responderConfirm());

        long sequence = p.alice().nextSendSequence();
        String cipherText = SessionCrypto.encrypt(
                "hello bob", p.alice().getSendKey(), "alice", "bob", sequence);

        long expected = p.bob().nextExpectedSequence();
        String plainText = SessionCrypto.decrypt(
                cipherText, p.bob().getReceiveKey(), "alice", "bob", expected);
        assertEquals(plainText, "hello bob");
        p.bob().markReceived(expected);

        // The same frame must not be accepted twice.
        try {
            p.bob().markReceived(expected);
            fail("replay must be rejected");
        } catch (Exception expectedFailure) {
            // expected
        }
    }

    @Test
    public void freshSessionIsNotExpired() throws Exception {
        KeyPair dummy = EcdhCrypto.generateKeyPair();
        SessionContext ctx = new SessionContext(
                "alice", "bob", dummy, SessionContext.Role.INITIATOR);
        assertFalse(ctx.isExpired());
    }

    @Test
    public void touchUpdatesActivity() throws Exception {
        KeyPair dummy = EcdhCrypto.generateKeyPair();
        SessionContext ctx = new SessionContext(
                "alice", "bob", dummy, SessionContext.Role.INITIATOR);
        var before = ctx.getLastActivityAt();
        Thread.sleep(10);
        ctx.touch();
        assertTrue(ctx.getLastActivityAt().isAfter(before));
    }

    @Test
    public void destroyWipesKeys() throws Exception {
        Pair p = handshake();
        p.bob().completeAsResponder(p.bobKeys());
        p.alice().completeAsInitiator(p.aliceKeys(), p.aliceKeys().responderConfirm());

        p.alice().destroy();
        assertNull(p.alice().getSendKey());
        assertNull(p.alice().getReceiveKey());
        assertFalse(p.alice().isReady());
    }
}
