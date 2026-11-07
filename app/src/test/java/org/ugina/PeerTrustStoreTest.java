package org.ugina;

import org.testng.annotations.Test;
import org.ugina.client.PeerKeyMismatchException;
import org.ugina.client.PeerTrustStore;
import org.ugina.crypto.KeyFingerprint;
import org.ugina.crypto.RsaCrypto;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;

import static org.testng.Assert.*;

public class PeerTrustStoreTest {

    private Path newTrustFile() throws Exception {
        return Files.createTempDirectory("secure-chat-trust-").resolve("known-peers.tsv");
    }

    @Test
    public void firstContactPinsTheKeyAndPersistsIt() throws Exception {
        Path file = newTrustFile();
        KeyPair bob = RsaCrypto.generateKeyPair();

        PeerTrustStore store = new PeerTrustStore(file);
        assertEquals(store.verify("bob", bob.getPublic()),
                PeerTrustStore.Verification.FIRST_CONTACT);
        assertEquals(store.verify("bob", bob.getPublic()),
                PeerTrustStore.Verification.KNOWN);
        assertTrue(Files.exists(file));

        PeerTrustStore reloaded = new PeerTrustStore(file);
        assertEquals(reloaded.verify("bob", bob.getPublic()),
                PeerTrustStore.Verification.KNOWN);
    }

    @Test
    public void changedKeyIsRejectedAndKeptAsPending() throws Exception {
        Path file = newTrustFile();
        KeyPair bob = RsaCrypto.generateKeyPair();
        KeyPair mallory = RsaCrypto.generateKeyPair();

        PeerTrustStore store = new PeerTrustStore(file);
        store.verify("bob", bob.getPublic());

        try {
            store.verify("bob", mallory.getPublic());
            fail("a changed key must be rejected");
        } catch (PeerKeyMismatchException e) {
            assertEquals(e.getUsername(), "bob");
            assertEquals(e.getExpectedFingerprint(), KeyFingerprint.hex(bob.getPublic()));
            assertEquals(e.getActualFingerprint(), KeyFingerprint.hex(mallory.getPublic()));
        }

        assertEquals(store.pinnedFingerprint("bob").orElseThrow(),
                KeyFingerprint.hex(bob.getPublic()));
        assertEquals(store.pendingFingerprint("bob").orElseThrow(),
                KeyFingerprint.hex(mallory.getPublic()));
    }

    @Test
    public void explicitTrustAcceptsTheNewKeyAfterVerification() throws Exception {
        Path file = newTrustFile();
        KeyPair bob = RsaCrypto.generateKeyPair();
        KeyPair newBob = RsaCrypto.generateKeyPair();

        PeerTrustStore store = new PeerTrustStore(file);
        store.verify("bob", bob.getPublic());
        try {
            store.verify("bob", newBob.getPublic());
            fail("a changed key must be rejected");
        } catch (PeerKeyMismatchException expected) {
            // expected
        }

        String prefix = KeyFingerprint.shortForm(KeyFingerprint.hex(newBob.getPublic()));
        assertEquals(KeyFingerprint.hex(store.trustPending("bob", prefix)),
                KeyFingerprint.hex(newBob.getPublic()));

        assertEquals(store.verify("bob", newBob.getPublic()),
                PeerTrustStore.Verification.KNOWN);
        assertTrue(store.pendingFingerprint("bob").isEmpty());
    }

    @Test
    public void wrongOrTooShortPrefixDoesNotChangeThePin() throws Exception {
        Path file = newTrustFile();
        KeyPair bob = RsaCrypto.generateKeyPair();
        KeyPair newBob = RsaCrypto.generateKeyPair();

        PeerTrustStore store = new PeerTrustStore(file);
        store.verify("bob", bob.getPublic());
        try {
            store.verify("bob", newBob.getPublic());
            fail("a changed key must be rejected");
        } catch (PeerKeyMismatchException expected) {
            // expected
        }

        try {
            store.trustPending("bob", "0000000000000000");
            fail("a wrong prefix must be rejected");
        } catch (IllegalArgumentException expected) {
            // expected
        }
        try {
            store.trustPending("bob", "abcd");
            fail("a short prefix must be rejected");
        } catch (IllegalArgumentException expected) {
            // expected
        }

        assertEquals(store.verify("bob", bob.getPublic()),
                PeerTrustStore.Verification.KNOWN);
    }

    @Test(expectedExceptions = IllegalStateException.class)
    public void trustWithoutAPendingKeyFails() throws Exception {
        Path file = newTrustFile();
        PeerTrustStore store = new PeerTrustStore(file);

        store.trustPending("bob", "a1b2c3d4e5f60718");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void invalidUsernameIsRejected() throws Exception {
        Path file = newTrustFile();
        KeyPair bob = RsaCrypto.generateKeyPair();
        PeerTrustStore store = new PeerTrustStore(file);

        store.verify("../../etc/passwd", bob.getPublic());
    }

    @Test
    public void twoStoreInstancesDoNotEraseEachOthersPins() throws Exception {
        Path file = newTrustFile();
        KeyPair alice = RsaCrypto.generateKeyPair();
        KeyPair bob = RsaCrypto.generateKeyPair();

        // Both stores are opened before either has written anything — this is
        // what happens when two chat windows run from the same desktop account.
        PeerTrustStore firstClient = new PeerTrustStore(file);
        PeerTrustStore secondClient = new PeerTrustStore(file);

        firstClient.verify("alice", alice.getPublic());
        secondClient.verify("bob", bob.getPublic());

        PeerTrustStore reloaded = new PeerTrustStore(file);
        assertEquals(reloaded.verify("alice", alice.getPublic()),
                PeerTrustStore.Verification.KNOWN);
        assertEquals(reloaded.verify("bob", bob.getPublic()),
                PeerTrustStore.Verification.KNOWN);
    }

    @Test
    public void staleStoreDoesNotUndoATrustDecisionMadeElsewhere() throws Exception {
        Path file = newTrustFile();
        KeyPair bob = RsaCrypto.generateKeyPair();
        KeyPair newBob = RsaCrypto.generateKeyPair();
        KeyPair alice = RsaCrypto.generateKeyPair();

        PeerTrustStore first = new PeerTrustStore(file);
        first.verify("bob", bob.getPublic());

        // This instance loads the file while bob still has the original key.
        PeerTrustStore stale = new PeerTrustStore(file);

        // Another process re-trusts bob's replacement key.
        PeerTrustStore other = new PeerTrustStore(file);
        other.verify("bob", bob.getPublic());
        try {
            other.verify("bob", newBob.getPublic());
            fail("a changed key must be rejected");
        } catch (PeerKeyMismatchException expected) {
            // expected
        }
        other.trustPending("bob",
                KeyFingerprint.shortForm(KeyFingerprint.hex(newBob.getPublic())));

        // The stale instance now pins alice and rewrites the whole file; it
        // must not write bob's outdated pin back.
        stale.verify("alice", alice.getPublic());

        PeerTrustStore reloaded = new PeerTrustStore(file);
        assertEquals(reloaded.verify("bob", newBob.getPublic()),
                PeerTrustStore.Verification.KNOWN);
        assertEquals(reloaded.verify("alice", alice.getPublic()),
                PeerTrustStore.Verification.KNOWN);
    }

    @Test(expectedExceptions = IllegalStateException.class)
    public void corruptTrustFileFailsClosed() throws Exception {
        Path file = newTrustFile();
        Files.createDirectories(file.getParent());
        Files.writeString(file, "bob\tnot-a-fingerprint\t123\n", StandardCharsets.UTF_8);

        new PeerTrustStore(file);
    }
}
