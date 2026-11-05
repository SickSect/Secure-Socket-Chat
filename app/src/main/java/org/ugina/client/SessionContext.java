package org.ugina.client;

import org.ugina.crypto.SessionCrypto;
import org.ugina.crypto.exception.CryptoException;

import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;

/**
 * One end-to-end session with a peer.
 *
 * <p>v2 state machine:</p>
 * <pre>
 * INITIATOR: WAITING_FOR_ACK --(ACK verified)--> READY
 * RESPONDER: WAITING_FOR_CONFIRM --(CONFIRM verified)--> READY
 * </pre>
 *
 * <p>The initiator only becomes usable after it has verified the responder's
 * key-confirmation tag. The responder only becomes usable after it has
 * verified the initiator's confirmation tag. This gives both sides explicit
 * proof that the other side derived the same transcript-bound key.</p>
 */
public class SessionContext {

    public enum State {
        WAITING_FOR_ACK,
        WAITING_FOR_CONFIRM,
        READY,
        FAILED
    }

    public enum Role {
        INITIATOR,
        RESPONDER
    }

    private final String ownName;
    private final String peerName;
    private final Role role;

    private KeyPair ephemeralKeyPair;
    private SecretKey sendKey;
    private SecretKey receiveKey;
    private byte[] ownConfirm;
    private byte[] expectedPeerConfirm;
    private byte[] transcriptHash;

    private volatile State state;
    private final CompletableFuture<Boolean> handshakeResult = new CompletableFuture<>();

    private long sendSequence = 0;
    private long lastReceivedSequence = -1;

    private static final Duration IDLE_TIMEOUT = Duration.ofMinutes(30);
    private static final Duration ABSOLUTE_TIMEOUT = Duration.ofHours(24);

    private final Instant createdAt;
    private volatile Instant lastActivityAt;

    public SessionContext(String ownName, String peerName, KeyPair ephemeralKeyPair, Role role) {
        this.ownName = ownName;
        this.peerName = peerName;
        this.role = role;
        this.ephemeralKeyPair = ephemeralKeyPair;
        this.state = role == Role.INITIATOR ? State.WAITING_FOR_ACK : State.WAITING_FOR_CONFIRM;
        this.createdAt = Instant.now();
        this.lastActivityAt = Instant.now();
    }

    /**
     * Install the keys on the initiator side and verify the responder's
     * confirmation tag. The handshake future is completed separately by
     * {@link #markEstablished()} so the caller can send SESSION_CONFIRM first.
     *
     * @return this side's confirmation tag that must be sent to the responder
     */
    public byte[] completeAsInitiator(SessionCrypto.DerivedKeys keys, byte[] peerConfirmation)
            throws CryptoException {
        if (state != State.WAITING_FOR_ACK) {
            throw new CryptoException("Unexpected state for initiator completion: " + state, null);
        }
        if (!SessionCrypto.constantTimeEquals(keys.responderConfirm(), peerConfirmation)) {
            throw new CryptoException("Responder key confirmation does not match", null);
        }

        this.sendKey = keys.initiatorToResponder();
        this.receiveKey = keys.responderToInitiator();
        this.ownConfirm = keys.initiatorConfirm();
        this.expectedPeerConfirm = keys.responderConfirm();
        this.transcriptHash = keys.transcriptHash();
        this.ephemeralKeyPair = null;
        this.state = State.READY;
        this.lastActivityAt = Instant.now();
        return ownConfirm;
    }

    /**
     * Install the keys on the responder side.
     *
     * @return this side's confirmation tag that must be sent in SESSION_ACK
     */
    public byte[] completeAsResponder(SessionCrypto.DerivedKeys keys) throws CryptoException {
        if (state != State.WAITING_FOR_CONFIRM) {
            throw new CryptoException("Unexpected state for responder completion: " + state, null);
        }

        this.sendKey = keys.responderToInitiator();
        this.receiveKey = keys.initiatorToResponder();
        this.ownConfirm = keys.responderConfirm();
        this.expectedPeerConfirm = keys.initiatorConfirm();
        this.transcriptHash = keys.transcriptHash();
        this.ephemeralKeyPair = null;
        this.state = State.WAITING_FOR_CONFIRM;
        this.lastActivityAt = Instant.now();
        return ownConfirm;
    }

    /**
     * Verify the initiator's confirmation tag and mark the responder session
     * usable.
     */
    public void confirmInitiator(byte[] confirmation) throws CryptoException {
        if (state != State.WAITING_FOR_CONFIRM) {
            throw new CryptoException("Session is not awaiting confirmation: " + state, null);
        }
        if (!SessionCrypto.constantTimeEquals(expectedPeerConfirm, confirmation)) {
            throw new CryptoException("Initiator key confirmation does not match", null);
        }
        state = State.READY;
        lastActivityAt = Instant.now();
        handshakeResult.complete(true);
    }

    /**
     * Called by the initiator after SESSION_CONFIRM has been sent.
     */
    public void markEstablished() {
        lastActivityAt = Instant.now();
        handshakeResult.complete(true);
    }

    public synchronized long nextSendSequence() {
        return sendSequence++;
    }

    public synchronized long nextExpectedSequence() {
        return lastReceivedSequence + 1;
    }

    /**
     * Advance the receive counter only after successful GCM authentication.
     */
    public synchronized void markReceived(long sequence) throws CryptoException {
        if (sequence != lastReceivedSequence + 1) {
            throw new CryptoException(
                    "Replay or gap detected: got " + sequence
                            + ", expected " + (lastReceivedSequence + 1), null);
        }
        lastReceivedSequence = sequence;
        lastActivityAt = Instant.now();
    }

    public void touch() {
        this.lastActivityAt = Instant.now();
    }

    public boolean isExpired() {
        Instant now = Instant.now();
        boolean idleExpired = Duration.between(lastActivityAt, now).compareTo(IDLE_TIMEOUT) > 0;
        boolean absoluteExpired = Duration.between(createdAt, now).compareTo(ABSOLUTE_TIMEOUT) > 0;
        return idleExpired || absoluteExpired;
    }

    public void failHandshake(String reason) {
        this.ephemeralKeyPair = null;
        this.state = State.FAILED;
        wipeMaterial();
        handshakeResult.complete(false);
    }

    /**
     * Explicitly destroy all cryptographic material for this session.
     */
    public void destroy() {
        state = State.FAILED;
        ephemeralKeyPair = null;
        wipeMaterial();
        if (!handshakeResult.isDone()) {
            handshakeResult.complete(false);
        }
    }

    private void wipeMaterial() {
        wipeKey(sendKey);
        wipeKey(receiveKey);
        sendKey = null;
        receiveKey = null;

        if (ownConfirm != null) {
            Arrays.fill(ownConfirm, (byte) 0);
            ownConfirm = null;
        }
        if (expectedPeerConfirm != null) {
            Arrays.fill(expectedPeerConfirm, (byte) 0);
            expectedPeerConfirm = null;
        }
        if (transcriptHash != null) {
            Arrays.fill(transcriptHash, (byte) 0);
            transcriptHash = null;
        }
    }

    private static void wipeKey(SecretKey key) {
        if (key instanceof Destroyable destroyable) {
            try {
                destroyable.destroy();
            } catch (Exception ignored) {
                // best effort
            }
        }
    }

    public String getOwnName() {
        return ownName;
    }

    public String getPeerName() {
        return peerName;
    }

    public Role getRole() {
        return role;
    }

    public State getState() {
        return state;
    }

    public boolean isReady() {
        return state == State.READY;
    }

    public PrivateKey getEphemeralPrivateKey() {
        return ephemeralKeyPair != null ? ephemeralKeyPair.getPrivate() : null;
    }

    public KeyPair getEphemeralKeyPair() {
        return ephemeralKeyPair;
    }

    public SecretKey getSendKey() {
        return sendKey;
    }

    public SecretKey getReceiveKey() {
        return receiveKey;
    }

    public byte[] getTranscriptHash() {
        return transcriptHash != null ? Arrays.copyOf(transcriptHash, transcriptHash.length) : null;
    }

    public CompletableFuture<Boolean> getHandshakeResult() {
        return handshakeResult;
    }

    public Instant getLastActivityAt() {
        return lastActivityAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
