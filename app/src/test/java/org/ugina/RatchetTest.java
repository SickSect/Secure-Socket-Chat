package org.ugina;

import org.testng.annotations.Test;
import org.ugina.client.SessionContext;
import org.ugina.crypto.EcdhCrypto;
import org.ugina.crypto.SessionCrypto;
import org.ugina.crypto.exception.CryptoException;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.testng.Assert.*;

/**
 * End-to-end ratchet behaviour without the network: two SessionContext
 * instances exchange real v3 payloads, which exercises convergence of the DH
 * ratchet, per-message key uniqueness, rotation cadence and replay/forgery
 * rejection exactly as ChatClientCore would drive them.
 */
public class RatchetTest {

    private record Pair(SessionContext alice, SessionContext bob) {
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

        byte[] responderConfirm = bob.completeAsResponder(bobKeys);
        byte[] initiatorConfirm = alice.completeAsInitiator(
                aliceKeys, responderConfirm, bobEphemeral.getPublic());
        alice.markEstablished();
        bob.confirmInitiator(initiatorConfirm);

        return new Pair(alice, bob);
    }

    /**
     * Sends one message and returns the parsed header so tests can assert on
     * the rotation flag. Verifies the plaintext on the receiving side.
     */
    private SessionCrypto.Header exchange(SessionContext sender, SessionContext receiver,
                                          String senderName, String receiverName,
                                          String text) throws Exception {
        SessionContext.SendTicket ticket = sender.beginSend();
        SessionCrypto.Header header = null;
        try {
            String payload = SessionCrypto.encrypt(text, ticket.messageKey(),
                    senderName, receiverName, ticket.sequence(), ticket.chainIndex(),
                    ticket.newRatchetPublicKey());

            header = SessionCrypto.parseHeader(payload);
            SessionContext.ReceivePlan plan = receiver.planReceive(header);
            try {
                String plain = SessionCrypto.decrypt(payload, plan.messageKey(),
                        senderName, receiverName, header.sequence(), header.chainIndex());
                assertEquals(plain, text, "plaintext must survive the ratchet");
                receiver.commitReceive(plan);
            } finally {
                plan.destroyMessageKey();
            }
        } finally {
            sender.commitSend(ticket);
            ticket.destroyMessageKey();
        }
        return header;
    }

    @Test
    public void multiTurnConversationConvergesWithRotationPerTurn() throws Exception {
        Pair p = handshake();

        // Turn 1: alice opens, bob answers — both first messages must carry
        // a fresh ratchet key; the rest of each burst must not.
        for (int i = 0; i < 3; i++) {
            SessionCrypto.Header h = exchange(p.alice(), p.bob(), "alice", "bob", "a1-" + i);
            assertEquals(h.hasNewRatchetKey(), i == 0,
                    "alice's first message of the turn must carry the ratchet key");
        }
        for (int i = 0; i < 3; i++) {
            SessionCrypto.Header h = exchange(p.bob(), p.alice(), "bob", "alice", "b1-" + i);
            assertEquals(h.hasNewRatchetKey(), i == 0,
                    "bob's first message of the turn must carry the ratchet key");
        }

        // Turn 2: each receive of a fresh peer key must trigger a rotation on
        // the next send — otherwise the chains would silently diverge.
        for (int i = 0; i < 3; i++) {
            SessionCrypto.Header h = exchange(p.alice(), p.bob(), "alice", "bob", "a2-" + i);
            assertEquals(h.hasNewRatchetKey(), i == 0, "alice must rotate each turn");
        }
        for (int i = 0; i < 3; i++) {
            SessionCrypto.Header h = exchange(p.bob(), p.alice(), "bob", "alice", "b2-" + i);
            assertEquals(h.hasNewRatchetKey(), i == 0, "bob must rotate each turn");
        }

        // A longer tail keeps chain indices moving across rotations.
        for (int turn = 0; turn < 4; turn++) {
            exchange(p.alice(), p.bob(), "alice", "bob", "tail-a" + turn);
            exchange(p.bob(), p.alice(), "bob", "alice", "tail-b" + turn);
        }
        assertEquals(p.alice().getSendSequence(), 10, "alice sends 3+3+4 messages");
        assertEquals(p.bob().getSendSequence(), 10, "bob sends 3+3+4 messages");
    }

    @Test
    public void everyMessageGetsItsOwnKey() throws Exception {
        Pair p = handshake();
        Set<String> messageKeys = new HashSet<>();

        for (int i = 0; i < 10; i++) {
            SessionContext.SendTicket ticket = p.alice().beginSend();
            try {
                String copy = java.util.Base64.getEncoder().encodeToString(
                        ticket.messageKey().getEncoded());
                assertTrue(messageKeys.add(copy),
                        "message key #" + i + " must be unique — per-message forward secrecy");
            } finally {
                ticket.destroyMessageKey();
                p.alice().commitSend(ticket);
            }
        }
        assertEquals(messageKeys.size(), 10);
    }

    @Test
    public void messageKeyOfOneMessageCannotOpenAnother() throws Exception {
        Pair p = handshake();

        SessionContext.SendTicket first = p.alice().beginSend();
        javax.crypto.SecretKey firstKey = first.messageKey();
        String firstPayload;
        try {
            firstPayload = SessionCrypto.encrypt("first", firstKey,
                    "alice", "bob", first.sequence(), first.chainIndex(),
                    first.newRatchetPublicKey());
        } finally {
            p.alice().commitSend(first);
        }

        SessionContext.SendTicket second = p.alice().beginSend();
        String secondPayload;
        try {
            secondPayload = SessionCrypto.encrypt("second", second.messageKey(),
                    "alice", "bob", second.sequence(), second.chainIndex(),
                    second.newRatchetPublicKey());
        } finally {
            second.destroyMessageKey();
            p.alice().commitSend(second);
        }

        SessionCrypto.Header header = SessionCrypto.parseHeader(secondPayload);
        try {
            SessionCrypto.decrypt(secondPayload, firstKey, "alice", "bob",
                    header.sequence(), header.chainIndex());
            fail("a leaked message key must not open other messages");
        } catch (CryptoException expectedFailure) {
            // expected
        }
        first.destroyMessageKey();
    }

    @Test
    public void rotationAdvancesTheRootKey() throws Exception {
        Pair p = handshake();
        byte[] rootAfterHandshake = p.bob().getRootKey();

        exchange(p.alice(), p.bob(), "alice", "bob", "trigger");

        byte[] rootAfterBobRatchet = p.bob().getRootKey();
        assertFalse(java.util.Arrays.equals(rootAfterHandshake, rootAfterBobRatchet),
                "receiving a fresh peer key must rekey the root");
        assertFalse(java.util.Arrays.equals(p.alice().getRootKey(), rootAfterHandshake),
                "the initiator's root must advance with the same step");

        exchange(p.bob(), p.alice(), "bob", "alice", "answer");
        assertFalse(java.util.Arrays.equals(p.alice().getRootKey(), rootAfterBobRatchet),
                "each rotation must produce a new root on both sides");
    }

    @Test
    public void payloadFromAnotherSessionIsRejected() throws Exception {
        Pair victim = handshake();
        Pair attacker = handshake();

        // A complete, valid message from a different session (same peers,
        // same starting sequence — only the root key differs).
        SessionContext.SendTicket ticket = attacker.alice().beginSend();
        String foreignPayload;
        try {
            foreignPayload = SessionCrypto.encrypt("evil", ticket.messageKey(),
                    "alice", "bob", ticket.sequence(), ticket.chainIndex(),
                    ticket.newRatchetPublicKey());
        } finally {
            ticket.destroyMessageKey();
            attacker.alice().commitSend(ticket);
        }

        try {
            SessionCrypto.Header header = SessionCrypto.parseHeader(foreignPayload);
            SessionContext.ReceivePlan plan = victim.bob().planReceive(header);
            SessionCrypto.decrypt(foreignPayload, plan.messageKey(), "alice", "bob",
                    header.sequence(), header.chainIndex());
            fail("a payload from another session must not decrypt");
        } catch (CryptoException expectedFailure) {
            // expected — and no plan was committed
        }
        assertFalse(victim.bob().hasReceiveChain(),
                "the victim's ratchet state must remain untouched");

        // The victim's real first message must still work afterwards.
        exchange(victim.alice(), victim.bob(), "alice", "bob", "legit");
    }

    @Test
    public void outOfOrderDeliveryIsRejected() throws Exception {
        Pair p = handshake();

        SessionContext.SendTicket ticket1 = p.alice().beginSend();
        String payload1;
        try {
            payload1 = SessionCrypto.encrypt("one", ticket1.messageKey(),
                    "alice", "bob", ticket1.sequence(), ticket1.chainIndex(),
                    ticket1.newRatchetPublicKey());
        } finally {
            ticket1.destroyMessageKey();
            p.alice().commitSend(ticket1);
        }
        SessionContext.SendTicket ticket2 = p.alice().beginSend();
        String payload2;
        try {
            payload2 = SessionCrypto.encrypt("two", ticket2.messageKey(),
                    "alice", "bob", ticket2.sequence(), ticket2.chainIndex(),
                    ticket2.newRatchetPublicKey());
        } finally {
            ticket2.destroyMessageKey();
            p.alice().commitSend(ticket2);
        }

        // Deliver the second message first: the strict sequence check must
        // reject it before any ratchet work happens.
        try {
            p.bob().planReceive(SessionCrypto.parseHeader(payload2));
            fail("gap in the sequence must be rejected");
        } catch (CryptoException expectedFailure) {
            // expected
        }
        assertFalse(p.bob().hasReceiveChain());

        // In-order delivery still works.
        SessionCrypto.Header header = SessionCrypto.parseHeader(payload1);
        SessionContext.ReceivePlan plan = p.bob().planReceive(header);
        assertEquals(SessionCrypto.decrypt(payload1, plan.messageKey(),
                "alice", "bob", header.sequence(), header.chainIndex()), "one");
        p.bob().commitReceive(plan);
        plan.destroyMessageKey();

        header = SessionCrypto.parseHeader(payload2);
        plan = p.bob().planReceive(header);
        assertEquals(SessionCrypto.decrypt(payload2, plan.messageKey(),
                "alice", "bob", header.sequence(), header.chainIndex()), "two");
        p.bob().commitReceive(plan);
        plan.destroyMessageKey();
    }

    @Test
    public void rawRatchetPointsRoundTrip() throws Exception {
        List<byte[]> raws = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            KeyPair pair = EcdhCrypto.generateKeyPair();
            byte[] raw = EcdhCrypto.publicKeyToRaw(pair.getPublic());
            assertEquals(raw.length, 65);
            assertEquals(raw[0], 0x04);
            java.security.PublicKey restored = EcdhCrypto.publicKeyFromRaw(raw);
            assertTrue(java.util.Arrays.equals(EcdhCrypto.publicKeyToRaw(restored), raw),
                    "raw point must round-trip through the key factory");
            raws.add(raw);
        }
        for (int i = 0; i < raws.size(); i++) {
            for (int j = i + 1; j < raws.size(); j++) {
                assertFalse(java.util.Arrays.equals(raws.get(i), raws.get(j)));
            }
        }
    }

    @Test(expectedExceptions = CryptoException.class)
    public void rawPointOffCurveIsRejected() throws Exception {
        byte[] raw = EcdhCrypto.publicKeyToRaw(EcdhCrypto.generateKeyPair().getPublic());
        raw[64] ^= 0x01; // move Y off the curve
        EcdhCrypto.publicKeyFromRaw(raw);
    }

    @Test(expectedExceptions = CryptoException.class)
    public void rawPointWrongLengthIsRejected() throws Exception {
        EcdhCrypto.publicKeyFromRaw(new byte[64]);
    }
}
