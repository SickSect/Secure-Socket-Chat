package org.ugina;

import org.testng.annotations.Test;
import org.ugina.client.SessionContext;
import org.ugina.crypto.EcdhCrypto;
import org.ugina.crypto.SessionCrypto;

import java.security.KeyPair;
import java.security.PublicKey;

import static org.testng.Assert.*;

public class SessionContextTest {

    private record Pair(SessionContext alice, SessionContext bob,
                        SessionCrypto.DerivedKeys aliceKeys,
                        SessionCrypto.DerivedKeys bobKeys,
                        PublicKey bobRatchetPub) {
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
        return new Pair(alice, bob, aliceKeys, bobKeys, bobEphemeral.getPublic());
    }

    private void complete(Pair p) throws Exception {
        byte[] responderConfirm = p.bob().completeAsResponder(p.bobKeys());
        byte[] initiatorConfirm = p.alice().completeAsInitiator(
                p.aliceKeys(), responderConfirm, p.bobRatchetPub());
        p.alice().markEstablished();
        p.bob().confirmInitiator(initiatorConfirm);
    }

    @Test
    public void handshakeRequiresKeyConfirmation() throws Exception {
        Pair p = handshake();

        byte[] responderConfirm = p.bob().completeAsResponder(p.bobKeys());
        assertFalse(p.bob().isReady(), "responder must wait for the initiator's confirmation");

        byte[] initiatorConfirm = p.alice().completeAsInitiator(
                p.aliceKeys(), responderConfirm, p.bobRatchetPub());
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
        p.alice().completeAsInitiator(p.aliceKeys(), new byte[32], p.bobRatchetPub());
    }

    @Test
    public void bothSidesShareTheSameRootKey() throws Exception {
        Pair p = handshake();
        complete(p);

        byte[] aliceRoot = p.alice().getRootKey();
        byte[] bobRoot = p.bob().getRootKey();
        assertNotNull(aliceRoot);
        assertEquals(aliceRoot, bobRoot,
                "handshake must install an identical ratchet root on both sides");
    }

    @Test
    public void firstMessageCarriesRatchetKeyAndBobCanDecrypt() throws Exception {
        Pair p = handshake();
        complete(p);

        SessionContext.SendTicket ticket = p.alice().beginSend();
        try {
            assertNotNull(ticket.newRatchetPublicKey(),
                    "the initiator's first message must carry its ratchet key");
            String payload = SessionCrypto.encrypt("hello bob", ticket.messageKey(),
                    "alice", "bob", ticket.sequence(), ticket.chainIndex(),
                    ticket.newRatchetPublicKey());

            SessionCrypto.Header header = SessionCrypto.parseHeader(payload);
            SessionContext.ReceivePlan plan = p.bob().planReceive(header);
            assertTrue(plan.ratcheted(), "the responder must perform its first ratchet step");
            String plain = SessionCrypto.decrypt(payload, plan.messageKey(),
                    "alice", "bob", header.sequence(), header.chainIndex());
            assertEquals(plain, "hello bob");
            p.bob().commitReceive(plan);
        } finally {
            ticket.destroyMessageKey();
        }

        assertTrue(p.bob().hasSendChain(),
                "the first ratchet step must create the responder's send chain");
        assertTrue(p.bob().hasReceiveChain());
    }

    @Test
    public void replayedMessageIsRejected() throws Exception {
        Pair p = handshake();
        complete(p);

        SessionContext.SendTicket ticket = p.alice().beginSend();
        String payload;
        try {
            payload = SessionCrypto.encrypt("once", ticket.messageKey(),
                    "alice", "bob", ticket.sequence(), ticket.chainIndex(),
                    ticket.newRatchetPublicKey());
        } finally {
            ticket.destroyMessageKey();
        }
        p.alice().commitSend(ticket);

        SessionCrypto.Header header = SessionCrypto.parseHeader(payload);
        SessionContext.ReceivePlan plan = p.bob().planReceive(header);
        SessionCrypto.decrypt(payload, plan.messageKey(), "alice", "bob",
                header.sequence(), header.chainIndex());
        p.bob().commitReceive(plan);
        plan.destroyMessageKey();

        // The very same frame a second time must fail the sequence check.
        try {
            p.bob().planReceive(SessionCrypto.parseHeader(payload));
            fail("replay must be rejected");
        } catch (Exception expectedFailure) {
            // expected
        }
    }

    @Test
    public void forgedMessageCannotCorruptRatchetState() throws Exception {
        Pair p = handshake();
        complete(p);

        SessionContext.SendTicket ticket = p.alice().beginSend();
        String payload;
        try {
            payload = SessionCrypto.encrypt("real", ticket.messageKey(),
                    "alice", "bob", ticket.sequence(), ticket.chainIndex(),
                    ticket.newRatchetPublicKey());
        } finally {
            ticket.destroyMessageKey();
        }

        // Flip one ciphertext byte: the plan (including the ratchet step) is
        // computed, decryption fails, and nothing is committed.
        byte[] rootBefore = p.bob().getRootKey();
        byte[] bytes = java.util.Base64.getDecoder().decode(payload);
        bytes[bytes.length - 1] ^= 0x01;
        String forged = java.util.Base64.getEncoder().encodeToString(bytes);

        try {
            SessionCrypto.Header forgedHeader = SessionCrypto.parseHeader(forged);
            SessionContext.ReceivePlan forgedPlan = p.bob().planReceive(forgedHeader);
            SessionCrypto.decrypt(forged, forgedPlan.messageKey(), "alice", "bob",
                    forgedHeader.sequence(), forgedHeader.chainIndex());
            fail("forged message must not authenticate");
        } catch (Exception expectedFailure) {
            // expected — no commit happened
        }
        assertBytesEqual(p.bob().getRootKey(), rootBefore,
                "a failed plan must not move the ratchet root");
        assertTrue(p.bob().isReady());
        assertFalse(p.bob().hasReceiveChain(), "discarded plan must not install state");

        // The original, untampered message must still be accepted afterwards.
        SessionCrypto.Header header = SessionCrypto.parseHeader(payload);
        SessionContext.ReceivePlan plan = p.bob().planReceive(header);
        String plain = SessionCrypto.decrypt(payload, plan.messageKey(),
                "alice", "bob", header.sequence(), header.chainIndex());
        assertEquals(plain, "real");
        p.bob().commitReceive(plan);
        plan.destroyMessageKey();
        assertTrue(p.bob().hasReceiveChain());
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
        complete(p);
        // Establish chains so there is something to wipe.
        SessionContext.SendTicket ticket = p.alice().beginSend();
        ticket.destroyMessageKey();
        p.alice().commitSend(ticket);

        p.alice().destroy();
        assertNull(p.alice().getRootKey());
        assertFalse(p.alice().hasSendChain());
        assertFalse(p.alice().isReady());
    }

    private static void assertBytesEqual(byte[] actual, byte[] expected, String message) {
        assertTrue(java.util.Arrays.equals(actual, expected), message);
    }
}
