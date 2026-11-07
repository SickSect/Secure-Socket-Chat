package org.ugina.client;

import org.ugina.crypto.DestroyableSecretKey;
import org.ugina.crypto.EcdhCrypto;
import org.ugina.crypto.SessionCrypto;
import org.ugina.crypto.exception.CryptoException;

import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;

/**
 * One end-to-end session with a peer — state machine plus ratchet state.
 *
 * <p>Handshake state machine (unchanged from v2):</p>
 * <pre>
 * INITIATOR: WAITING_FOR_ACK --(ACK verified)--> READY
 * RESPONDER: WAITING_FOR_CONFIRM --(CONFIRM verified)--> READY
 * </pre>
 *
 * <p>Ratchet state (v3): both sides share a root key. Each direction carries
 * traffic through a chain key; every message advances its chain one step and
 * uses a single-use message key. The root key only changes during a DH-ratchet
 * step, which happens exclusively when a message arrives with the peer's
 * fresh ratchet public key. That receive-triggered rule forces strict
 * alternation, so both sides apply the same sequence of root derivations and
 * always converge on the same chains.</p>
 *
 * <p>State changes are two-phase ({@link #beginSend}/{@link #commitSend},
 * {@link #planReceive}/{@link #commitReceive}): all values are computed into a
 * ticket/plan first and only installed after the GCM tag has been verified,
 * so a forged message can never corrupt the ratchet state.</p>
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

    /**
     * Everything needed to encrypt one message. The state is only advanced
     * when {@link #commitSend} is called after a successful write.
     */
    public record SendTicket(
            long sequence,
            long chainIndex,
            SecretKey messageKey,
            byte[] newRatchetPublicKey,
            byte[] nextSendChain
    ) {
        public void destroyMessageKey() {
            wipeKey(messageKey);
        }
    }

    /**
     * Result of validating an incoming header. Contains the single-use
     * message key plus — when the header carried a fresh ratchet key — the
     * fully derived replacement state. Nothing is installed until
     * {@link #commitReceive} runs after successful decryption.
     */
    public record ReceivePlan(
            long sequence,
            long chainIndex,
            SecretKey messageKey,
            byte[] nextReceiveChain,
            boolean ratcheted,
            byte[] newRootKey,
            byte[] newSendChain,
            PublicKey newPeerRatchetKey,
            KeyPair newRatchetKeyPair
    ) {
        public void destroyMessageKey() {
            wipeKey(messageKey);
        }
    }

    private final String ownName;
    private final String peerName;
    private final Role role;

    /** Own ratchet DH key pair (DHs); starts as the handshake ephemeral key. */
    private KeyPair ratchetKeyPair;
    /** Peer's current ratchet public key (DHr); null for the responder until the first message. */
    private PublicKey peerRatchetKey;
    /** Shared root key of the DH ratchet. */
    private byte[] rootKey;
    /** Sending / receiving chain keys (symmetric ratchet). */
    private byte[] sendChain;
    private byte[] receiveChain;
    /** True until the first message carrying the current ratchet key is sent. */
    private boolean sendChainFresh;
    private long sendChainIndex;
    private long receiveChainIndex;

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
        this.ratchetKeyPair = ephemeralKeyPair;
        this.state = role == Role.INITIATOR ? State.WAITING_FOR_ACK : State.WAITING_FOR_CONFIRM;
        this.createdAt = Instant.now();
        this.lastActivityAt = Instant.now();
    }

    /**
     * Install the ratchet root on the initiator side and verify the
     * responder's confirmation tag. The initiator already knows the peer's
     * ratchet key (the responder's handshake ephemeral), so it can derive its
     * initial sending chain lazily on the first {@link #beginSend()}.
     *
     * @param peerRatchetKey the responder's ephemeral public key from SESSION_ACK
     * @return this side's confirmation tag that must be sent to the responder
     */
    public synchronized byte[] completeAsInitiator(
            SessionCrypto.DerivedKeys keys,
            byte[] peerConfirmation,
            PublicKey peerRatchetKey
    ) throws CryptoException {
        if (state != State.WAITING_FOR_ACK) {
            throw new CryptoException("Unexpected state for initiator completion: " + state, null);
        }
        if (peerRatchetKey == null) {
            throw new CryptoException("Missing responder ratchet key", null);
        }
        if (!SessionCrypto.constantTimeEquals(keys.responderConfirm(), peerConfirmation)) {
            throw new CryptoException("Responder key confirmation does not match", null);
        }

        this.rootKey = keys.rootKey();
        this.peerRatchetKey = peerRatchetKey;
        this.sendChain = null;          // derived lazily on first send
        this.receiveChain = null;       // arrives with the responder's first message
        this.sendChainIndex = 0;
        this.receiveChainIndex = 0;
        this.sendChainFresh = true;     // first message must carry our ratchet key
        this.ownConfirm = keys.initiatorConfirm();
        this.expectedPeerConfirm = keys.responderConfirm();
        this.transcriptHash = keys.transcriptHash();
        this.state = State.READY;
        this.lastActivityAt = Instant.now();
        return ownConfirm;
    }

    /**
     * Install the ratchet root on the responder side. The peer's ratchet key
     * is deliberately left null: the initiator's first message carries it and
     * triggers the first DH-ratchet step (which also creates our sending
     * chain, so the responder can never send before receiving).
     *
     * @return this side's confirmation tag that must be sent in SESSION_ACK
     */
    public synchronized byte[] completeAsResponder(SessionCrypto.DerivedKeys keys)
            throws CryptoException {
        if (state != State.WAITING_FOR_CONFIRM) {
            throw new CryptoException("Unexpected state for responder completion: " + state, null);
        }

        this.rootKey = keys.rootKey();
        this.peerRatchetKey = null;
        this.sendChain = null;
        this.receiveChain = null;
        this.sendChainIndex = 0;
        this.receiveChainIndex = 0;
        this.sendChainFresh = false;
        this.ownConfirm = keys.responderConfirm();
        this.expectedPeerConfirm = keys.initiatorConfirm();
        this.transcriptHash = keys.transcriptHash();
        this.state = State.WAITING_FOR_CONFIRM;
        this.lastActivityAt = Instant.now();
        return ownConfirm;
    }

    /**
     * Verify the initiator's confirmation tag and mark the responder session
     * usable.
     */
    public synchronized void confirmInitiator(byte[] confirmation) throws CryptoException {
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

    /**
     * Prepares the next outgoing message: selects/derives the single-use
     * message key and, when the sending chain was just (re)derived, attaches
     * this side's current ratchet public key so the peer can follow the
     * rotation. No state changes until {@link #commitSend}.
     */
    public synchronized SendTicket beginSend() throws CryptoException {
        if (state != State.READY) {
            throw new CryptoException("Session is not ready: " + state, null);
        }
        if (sendChain == null) {
            // Initiator's first message: derive the initial sending chain from
            // the handshake root and the peer's known ratchet key. The peer
            // performs the identical KDF step when this message arrives.
            if (rootKey == null || ratchetKeyPair == null || peerRatchetKey == null) {
                throw new CryptoException("Cannot derive the initial send chain", null);
            }
            byte[] dhSecret = EcdhCrypto.computeSharedSecret(
                    ratchetKeyPair.getPrivate(), peerRatchetKey);
            try {
                SessionCrypto.RatchetStep step = SessionCrypto.kdfRk(rootKey, dhSecret, sendDirection());
                wipe(rootKey);
                rootKey = step.rootKey();
                sendChain = step.chainKey();
            } finally {
                wipe(dhSecret);
            }
            sendChainIndex = 0;
            sendChainFresh = true;
        }

        long sequence = sendSequence;
        long chainIndex = sendChainIndex;
        SessionCrypto.ChainStep step = SessionCrypto.kdfCk(sendChain);
        byte[] newRatchetPublicKey = sendChainFresh
                ? EcdhCrypto.publicKeyToRaw(ratchetKeyPair.getPublic())
                : null;
        lastActivityAt = Instant.now();
        return new SendTicket(sequence, chainIndex,
                new DestroyableSecretKey(step.messageKey(), "AES"),
                newRatchetPublicKey,
                step.nextChainKey());
    }

    /** Installs the send ticket after the message has been written to the wire. */
    public synchronized void commitSend(SendTicket ticket) {
        if (sendSequence != ticket.sequence() || sendChainIndex != ticket.chainIndex()) {
            throw new IllegalStateException("Stale send ticket");
        }
        sendSequence = ticket.sequence() + 1;
        sendChainIndex = ticket.chainIndex() + 1;
        byte[] oldChain = sendChain;
        sendChain = ticket.nextSendChain();
        wipe(oldChain);
        sendChainFresh = false;
        lastActivityAt = Instant.now();
    }

    /**
     * Validates an incoming header against the ratchet state and pre-computes
     * everything needed to decrypt it: the strict sequence check, an optional
     * DH-ratchet step (only when the header carries a fresh peer key), the
     * chain index, and the single-use message key. Purely computational —
     * on any failure or a bad GCM tag the plan is simply discarded and the
     * session state remains untouched.
     */
    public synchronized ReceivePlan planReceive(SessionCrypto.Header header) throws CryptoException {
        if (state != State.READY) {
            throw new CryptoException("Session is not ready: " + state, null);
        }
        if (header.sequence() != lastReceivedSequence + 1) {
            throw new CryptoException(
                    "Replay or gap detected: got " + header.sequence()
                            + ", expected " + (lastReceivedSequence + 1), null);
        }

        boolean wantsRatchet = header.hasNewRatchetKey();
        long expectedChainIndex = wantsRatchet ? 0 : receiveChainIndex;
        if (header.chainIndex() != expectedChainIndex) {
            throw new CryptoException(
                    "Unexpected chain index: got " + header.chainIndex()
                            + ", expected " + expectedChainIndex, null);
        }
        if (!wantsRatchet && receiveChain == null) {
            throw new CryptoException("No receive chain for this message", null);
        }

        byte[] newRootKey = null;
        byte[] newSendChain = null;
        PublicKey newPeerRatchetKey = null;
        KeyPair newRatchetKeyPair = null;
        byte[] effectiveReceiveChain = receiveChain;

        if (wantsRatchet) {
            if (rootKey == null || ratchetKeyPair == null || header.ratchetPublicKey() == null) {
                throw new CryptoException("Missing ratchet state", null);
            }
            PublicKey theirKey = EcdhCrypto.publicKeyFromRaw(header.ratchetPublicKey());

            // Step 1: open a new receiving chain for peer → us traffic.
            byte[] dhSecret1 = EcdhCrypto.computeSharedSecret(
                    ratchetKeyPair.getPrivate(), theirKey);
            SessionCrypto.RatchetStep step1;
            try {
                step1 = SessionCrypto.kdfRk(rootKey, dhSecret1, receiveDirection());
            } finally {
                wipe(dhSecret1);
            }

            // Step 2: rotate our own ratchet key and open a new sending chain
            // for us → peer traffic. Strictly alternating with the peer, so
            // both sides apply the same root-key sequence.
            KeyPair ownNewKeyPair = EcdhCrypto.generateKeyPair();
            byte[] dhSecret2 = EcdhCrypto.computeSharedSecret(
                    ownNewKeyPair.getPrivate(), theirKey);
            SessionCrypto.RatchetStep step2;
            try {
                step2 = SessionCrypto.kdfRk(step1.rootKey(), dhSecret2, sendDirection());
            } finally {
                wipe(dhSecret2);
            }

            newRootKey = step2.rootKey();
            newSendChain = step2.chainKey();
            newPeerRatchetKey = theirKey;
            newRatchetKeyPair = ownNewKeyPair;
            effectiveReceiveChain = step1.chainKey();
        }

        SessionCrypto.ChainStep chainStep = SessionCrypto.kdfCk(effectiveReceiveChain);
        return new ReceivePlan(
                header.sequence(),
                header.chainIndex(),
                new DestroyableSecretKey(chainStep.messageKey(), "AES"),
                chainStep.nextChainKey(),
                wantsRatchet,
                newRootKey,
                newSendChain,
                newPeerRatchetKey,
                newRatchetKeyPair);
    }

    /** Installs a verified receive plan after GCM authentication succeeded. */
    public synchronized void commitReceive(ReceivePlan plan) {
        if (plan.ratcheted()) {
            wipe(rootKey);
            rootKey = plan.newRootKey();
            ratchetKeyPair = plan.newRatchetKeyPair();
            peerRatchetKey = plan.newPeerRatchetKey();
            byte[] oldSendChain = sendChain;
            sendChain = plan.newSendChain();
            wipe(oldSendChain);
            sendChainIndex = 0;
            sendChainFresh = true;
        }
        wipe(receiveChain);
        receiveChain = plan.nextReceiveChain();
        receiveChainIndex = plan.chainIndex() + 1;
        lastReceivedSequence = plan.sequence();
        lastActivityAt = Instant.now();
    }

    private String sendDirection() {
        return role == Role.INITIATOR ? "i2r" : "r2i";
    }

    private String receiveDirection() {
        return role == Role.INITIATOR ? "r2i" : "i2r";
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
        this.ratchetKeyPair = null;
        this.state = State.FAILED;
        wipeMaterial();
        handshakeResult.complete(false);
    }

    /**
     * Explicitly destroy all cryptographic material for this session.
     */
    public void destroy() {
        state = State.FAILED;
        ratchetKeyPair = null;
        wipeMaterial();
        if (!handshakeResult.isDone()) {
            handshakeResult.complete(false);
        }
    }

    private void wipeMaterial() {
        wipe(rootKey);
        rootKey = null;
        wipe(sendChain);
        sendChain = null;
        wipe(receiveChain);
        receiveChain = null;
        peerRatchetKey = null;

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

    private static void wipe(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
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
        return ratchetKeyPair != null ? ratchetKeyPair.getPrivate() : null;
    }

    public KeyPair getEphemeralKeyPair() {
        return ratchetKeyPair;
    }

    /** Copy of the shared ratchet root key, or {@code null} after destroy. */
    public synchronized byte[] getRootKey() {
        return rootKey != null ? rootKey.clone() : null;
    }

    public synchronized boolean hasSendChain() {
        return sendChain != null;
    }

    public synchronized boolean hasReceiveChain() {
        return receiveChain != null;
    }

    public synchronized long getSendSequence() {
        return sendSequence;
    }

    public synchronized long getLastReceivedSequence() {
        return lastReceivedSequence;
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
