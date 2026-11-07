package org.ugina.client;

import org.testng.annotations.Test;
import org.ugina.crypto.RsaCrypto;
import org.ugina.crypto.RsaSignature;
import org.ugina.crypto.SessionCrypto;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.concurrent.atomic.AtomicInteger;

import static org.testng.Assert.*;

/**
 * The retry-with-fresh-key logic that turns a stale cached key (the peer
 * rotated its identity key while our connection was up) into the proper
 * /trust flow instead of a bare BAD_SIGNATURE.
 */
public class SignatureVerifyTest {

    private static final ChatEventListener NOOP_LISTENER = new ChatEventListener() {
        @Override
        public void onMessage(String from, String text) {
        }

        @Override
        public void onDelivered() {
        }

        @Override
        public void onError(String code, String text) {
        }

        @Override
        public void onSystem(String text) {
        }

        @Override
        public void onConnectionLost() {
        }

        @Override
        public void onDecryptionFailed(String from) {
        }
    };

    private ChatClientCore core() {
        Path trustFile = Path.of(System.getProperty("java.io.tmpdir"),
                "sig-verify-" + System.nanoTime() + ".tsv");
        return new ChatClientCore(NOOP_LISTENER, "localhost", 5000,
                new PeerTrustStore(trustFile));
    }

    private static byte[] payload() {
        return SessionCrypto.signingPayload("ack", "alice", "bob",
                "ephemeral".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void validCachedKeyVerifiesWithoutRefetch() throws Exception {
        KeyPair alice = RsaCrypto.generateKeyPair();
        byte[] payload = payload();
        byte[] signature = RsaSignature.sign(payload, alice.getPrivate());
        AtomicInteger refetches = new AtomicInteger();

        boolean ok = core().verifyPeerSignature(payload, signature, "alice",
                alice.getPublic(),
                name -> {
                    refetches.incrementAndGet();
                    return alice.getPublic();
                });

        assertTrue(ok, "a valid cached key must verify");
        assertEquals(refetches.get(), 0, "no refetch while the cached key works");
    }

    @Test
    public void staleCachedKeyIsReplacedByAFreshFetch() throws Exception {
        KeyPair staleKey = RsaCrypto.generateKeyPair();      // what keyCache holds
        KeyPair rotatedKey = RsaCrypto.generateKeyPair();    // the peer's real new key
        byte[] payload = payload();
        byte[] signature = RsaSignature.sign(payload, rotatedKey.getPrivate());
        AtomicInteger refetches = new AtomicInteger();

        boolean ok = core().verifyPeerSignature(payload, signature, "alice",
                staleKey.getPublic(),
                name -> {
                    refetches.incrementAndGet();
                    return rotatedKey.getPublic();
                });

        assertTrue(ok, "the retry with the fetched key must succeed");
        assertEquals(refetches.get(), 1, "exactly one refetch");
    }

    @Test
    public void forgedSignatureFailsEvenAfterRefetch() throws Exception {
        KeyPair victim = RsaCrypto.generateKeyPair();
        KeyPair attacker = RsaCrypto.generateKeyPair();
        byte[] payload = payload();
        byte[] signature = RsaSignature.sign(payload, attacker.getPrivate());
        AtomicInteger refetches = new AtomicInteger();

        boolean ok = core().verifyPeerSignature(payload, signature, "alice",
                victim.getPublic(),
                name -> {
                    refetches.incrementAndGet();
                    return victim.getPublic();
                });

        assertFalse(ok, "a forged signature must fail");
        assertEquals(refetches.get(), 1, "the retry still runs once");
    }

    @Test
    public void missingCachedKeyFetchesBeforeVerifying() throws Exception {
        KeyPair alice = RsaCrypto.generateKeyPair();
        byte[] payload = payload();
        byte[] signature = RsaSignature.sign(payload, alice.getPrivate());
        AtomicInteger refetches = new AtomicInteger();

        boolean ok = core().verifyPeerSignature(payload, signature, "alice",
                null,
                name -> {
                    refetches.incrementAndGet();
                    return alice.getPublic();
                });

        assertTrue(ok);
        assertEquals(refetches.get(), 1);
    }
}
