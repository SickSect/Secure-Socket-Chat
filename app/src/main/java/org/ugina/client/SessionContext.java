package org.ugina.client;

import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
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

    private static final Duration IDLE_TIMEOUT = Duration.ofMinutes(30);
    private static final Duration ABSOLUTE_TIMEOUT = Duration.ofHours(24);

    private final Instant createdAt;       // когда создана
    private volatile Instant lastActivityAt; // последнее использование

    public SessionContext(String peerName, KeyPair ephemeralKeyPair) {
        this.peerName = peerName;
        this.ephemeralKeyPair = ephemeralKeyPair;
        this.state = State.WAITING_FOR_ACK;
        this.sessionKey = null;
        this.handshakeResult = new CompletableFuture<>();
        this.createdAt = Instant.now();
        this.lastActivityAt = Instant.now();
    }


    public void completeHandshake(byte[] sessionKeyBytes){
        this.sessionKey = new DestroyableSecretKey(sessionKeyBytes, "AES");  // ← было SecretKeySpec
        this.ephemeralKeyPair = null;
        this.state = State.READY;
        this.lastActivityAt = Instant.now();
        this.handshakeResult.complete(true);
    }

    public void touch(){
        this.lastActivityAt = Instant.now();
    }

    public boolean isExpired(){
        Instant now = Instant.now();
        boolean idleExpired = Duration.between(lastActivityAt, now).compareTo(IDLE_TIMEOUT) > 0;
        boolean absoluteExpired = Duration.between(createdAt, now).compareTo(ABSOLUTE_TIMEOUT) > 0;
        return idleExpired || absoluteExpired;
    }

    public void failHandshake(String reason){
        this.ephemeralKeyPair = null;
        this.state = State.FAILED;
        this.handshakeResult.complete(false);
    }

    /**
     * Явно уничтожить криптографический материал сессии.
     * Затирает session_key (через его собственный destroy) и эфемерные ключи.
     * Вызывается когда сессия истекла или завершена.
     */
    public void destroy() {
        // Затираем session_key через его собственный destroy()
        // DestroyableSecretKey.destroy() занулит свой внутренний массив
        if (sessionKey instanceof Destroyable destroyable) {
            try {
                destroyable.destroy();
            } catch (Exception e) {
                // best effort — даже если не вышло, обнулим ссылку ниже
            }
        }
        sessionKey = null;

        // Обнуляем эфемерные ключи
        ephemeralKeyPair = null;

        // Помечаем что сессия мертва
        state = State.FAILED;
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

    public Instant getLastActivityAt() {
        return lastActivityAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
