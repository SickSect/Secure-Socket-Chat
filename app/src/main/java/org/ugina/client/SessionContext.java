package org.ugina.client;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.concurrent.CompletableFuture;

public class SessionContext {


    public enum State {
        WAITING_FOR_ACK,
        READY,
        FAILED
    }
    private KeyPair ephemeralKeyPair;
    private SecretKey sessionKey;
    private State state;
    private final CompletableFuture<Boolean> handshakeResult;
    private final String peerName;

    public SessionContext(String peerName, KeyPair ephemeralKeyPair) {
        this.peerName = peerName;
        this.ephemeralKeyPair = ephemeralKeyPair;
        this.state = State.WAITING_FOR_ACK;          // ← устанавливается внутри
        this.sessionKey = null;                       // ← (default, можно не писать)
        this.handshakeResult = new CompletableFuture<>();  // ← создаётся внутри
    }


    public void completeHandshake(byte[] sessionKeyBytes){
        this.sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");
        this.ephemeralKeyPair = null;
        this.state = State.READY;
        this.handshakeResult.complete(true);
    }

    public void failHandshake(String reason){
        this.ephemeralKeyPair = null;
        this.state = State.FAILED;
        this.handshakeResult.complete(false);
    }

    public String getPeerName() {
        return peerName;
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

    public SecretKey getSessionKey() {
        return sessionKey;
    }

    public CompletableFuture<Boolean> getHandshakeResult() {
        return handshakeResult;
    }
}
