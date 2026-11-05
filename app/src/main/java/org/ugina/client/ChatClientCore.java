package org.ugina.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.ugina.crypto.EcdhCrypto;
import org.ugina.crypto.RsaCrypto;
import org.ugina.crypto.RsaSignature;
import org.ugina.crypto.SessionCrypto;
import org.ugina.crypto.exception.CryptoException;
import org.ugina.protocol.ClientMessage;
import org.ugina.protocol.ErrorCode;
import org.ugina.protocol.ServerMessage;
import org.ugina.utils.FrameReader;

import javax.crypto.SecretKey;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class ChatClientCore {
    private static final int MAX_FRAME_CHARS = 96 * 1024;
    private static final int MAX_MESSAGE_CHARS = 32 * 1024;
    private static final int HANDSHAKE_TIMEOUT_SECONDS = 10;
    private static final int HANDSHAKE_THREADS = 4;

    private final ChatEventListener listener;
    private final String host;
    private final int port;

    private final ObjectMapper mapper = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    private final ConcurrentHashMap<String, PublicKey> keyCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, CompletableFuture<PublicKey>> pendingKeyRequests =
            new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, SessionContext> sessions = new ConcurrentHashMap<>();

    private final Object sessionLock = new Object();
    private final SecureRandom random = new SecureRandom();
    private final ExecutorService handshakeExecutor = Executors.newFixedThreadPool(
            HANDSHAKE_THREADS, runnable -> {
                Thread thread = new Thread(runnable, "handshake-worker");
                thread.setDaemon(true);
                return thread;
            });

    private SSLSocket sslSocket;
    private BufferedReader in;
    private PrintWriter out;
    private CompletableFuture<Boolean> joinResult;

    private String ownName;
    private PrivateKey privateKey;

    private volatile boolean connected = true;
    private volatile boolean sessionsDestroyed = false;

    public ChatClientCore(ChatEventListener listener, String host, int port) {
        this.listener = listener;
        this.host = host;
        this.port = port;
    }

    /**
     * Connects to the server with a JWT and the user's identity key pair.
     *
     * @param username name that will be used in the E2E transcript (must match
     *                 the JWT subject)
     * @param jwt      token obtained through REST login
     * @param keyPair  RSA identity key pair
     * @return true if JOIN succeeded
     */
    public boolean connect(String username, String jwt, KeyPair keyPair) throws Exception {
        if (username == null || username.isBlank() || jwt == null || keyPair == null) {
            throw new IllegalArgumentException("username, jwt and keyPair are required");
        }
        this.ownName = username;
        this.privateKey = keyPair.getPrivate();
        this.sessionsDestroyed = false;

        SSLContext sslContext = TlsClientContextFactory.createDefaultContext();
        System.out.println("Connecting to " + host + ":" + port + " via TLS...");
        try {
            sslSocket = (SSLSocket) sslContext.getSocketFactory().createSocket(host, port);
            SSLParameters sslParameters = sslSocket.getSSLParameters();
            sslParameters.setProtocols(new String[]{"TLSv1.3"});
            sslParameters.setEndpointIdentificationAlgorithm("HTTPS");
            sslSocket.setSSLParameters(sslParameters);
            sslSocket.setKeepAlive(true);
            sslSocket.setTcpNoDelay(true);
            sslSocket.startHandshake();

            System.out.println("TLS handshake successful. Protocol: "
                    + sslSocket.getSession().getProtocol()
                    + ", cipher: " + sslSocket.getSession().getCipherSuite());

            in = new BufferedReader(new InputStreamReader(
                    sslSocket.getInputStream(), StandardCharsets.UTF_8));
            out = new PrintWriter(new OutputStreamWriter(
                    sslSocket.getOutputStream(), StandardCharsets.UTF_8), true);
        } catch (Exception e) {
            closeSocketQuietly();
            throw new IllegalStateException("Could not connect to " + host + ":" + port
                    + " over TLS: " + e.getMessage(), e);
        }

        joinResult = new CompletableFuture<>();
        connected = true;
        startReaderThread();
        sendRaw(ClientMessage.join(jwt));
        try {
            return joinResult.get(HANDSHAKE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (Exception e) {
            disconnect();
            return false;
        }
    }

    public void disconnect() {
        try {
            if (out != null && connected) {
                sendRaw(ClientMessage.quit());
            }
        } catch (Exception ignored) {
            // best effort
        } finally {
            connected = false;
            closeSocketQuietly();
            destroyAllSessions();
        }
    }

    public void sendMessage(String recipient, String text) throws Exception {
        if (!connected) {
            listener.onError("DISCONNECTED", "Not connected to server");
            return;
        }
        if (text == null || text.length() > MAX_MESSAGE_CHARS) {
            listener.onError(ErrorCode.INVALID_FORMAT.name(),
                    "Message is empty or exceeds " + MAX_MESSAGE_CHARS + " characters");
            return;
        }

        SessionContext session = getOrEstablishSession(recipient);
        long sequence = session.nextSendSequence();
        String e2ePayload = SessionCrypto.encrypt(
                text, session.getSendKey(), ownName, recipient, sequence);

        byte[] nonceBytes = new byte[16];
        random.nextBytes(nonceBytes);
        String nonce = Base64.getEncoder().encodeToString(nonceBytes);

        sendRaw(ClientMessage.message(recipient, nonce, e2ePayload));
    }

    private void startReaderThread() {
        Thread thread = new Thread(() -> {
            try {
                String line;
                while ((line = FrameReader.readLine(in, MAX_FRAME_CHARS)) != null) {
                    ServerMessage msg = mapper.readValue(line, ServerMessage.class);
                    handleIncoming(msg);
                }
            } catch (Exception ex) {
                if (connected) {
                    System.err.println("[client] connection error: " + ex.getMessage());
                }
            } finally {
                connected = false;
                closeSocketQuietly();
                destroyAllSessions();
                listener.onConnectionLost();
            }
        }, "client-reader-thread");
        thread.setDaemon(true);
        thread.start();
    }

    private void instantiateHandshake(String peerName) throws Exception {
        PublicKey peerPublicKey = requestPublicKey(peerName);

        KeyPair ephemeralKeyPair = EcdhCrypto.generateKeyPair();
        byte[] ephemeralPubBytes = ephemeralKeyPair.getPublic().getEncoded();
        byte[] toSign = SessionCrypto.signingPayload("init", ownName, peerName, ephemeralPubBytes);
        byte[] signature = RsaSignature.sign(toSign, privateKey);

        SessionContext context = new SessionContext(
                ownName, peerName, ephemeralKeyPair, SessionContext.Role.INITIATOR);
        sessions.put(peerName, context);

        sendRaw(ClientMessage.initSession(
                peerName,
                EcdhCrypto.publicKeyToBase64(ephemeralKeyPair.getPublic()),
                Base64.getEncoder().encodeToString(signature)));
    }

    public void handleInitSession(ServerMessage msg) {
        try {
            handshakeExecutor.execute(() -> handleInitSessionAsync(msg));
        } catch (Exception e) {
            listener.onError("HANDSHAKE_FAILED", "Client is shutting down");
        }
    }

    private void handleInitSessionAsync(ServerMessage msg) {
        byte[] sharedSecret = null;
        try {
            String peerName = msg.fromClientName;
            if (peerName == null || msg.ephemeralPublicKey == null || msg.signature == null) {
                throw new CryptoException("Malformed INIT_SESSION", null);
            }

            PublicKey peerRsaPublicKey = requestPublicKey(peerName);
            PublicKey peerEphemeralPub = EcdhCrypto.publicKeyFromBase64(msg.ephemeralPublicKey);
            byte[] peerEphemeralBytes = peerEphemeralPub.getEncoded();
            byte[] toVerify = SessionCrypto.signingPayload(
                    "init", peerName, ownName, peerEphemeralBytes);
            byte[] signature = Base64.getDecoder().decode(msg.signature);

            if (!RsaSignature.verify(toVerify, signature, peerRsaPublicKey)) {
                listener.onError("BAD_SIGNATURE", "Invalid signature in INIT_SESSION from " + peerName);
                return;
            }

            KeyPair ownEphemeralKeyPair = EcdhCrypto.generateKeyPair();
            byte[] ownEphemeralBytes = ownEphemeralKeyPair.getPublic().getEncoded();
            sharedSecret = EcdhCrypto.computeSharedSecret(
                    ownEphemeralKeyPair.getPrivate(), peerEphemeralPub);

            SessionCrypto.DerivedKeys keys = SessionCrypto.derive(
                    sharedSecret, peerName, ownName, peerEphemeralBytes, ownEphemeralBytes);

            byte[] toSign = SessionCrypto.signingPayload(
                    "ack", ownName, peerName, ownEphemeralBytes);
            byte[] mySignature = RsaSignature.sign(toSign, privateKey);

            SessionContext context = new SessionContext(
                    ownName, peerName, ownEphemeralKeyPair, SessionContext.Role.RESPONDER);
            byte[] confirmation = context.completeAsResponder(keys);

            synchronized (sessionLock) {
                // Re-check and install atomically: the peer may have started
                // its own handshake while we were doing the ECDH work.
                if (!shouldAcceptIncomingHandshake(peerName)) {
                    context.destroy();
                    return;
                }
                if (sessions.putIfAbsent(peerName, context) != null) {
                    // A racing handshake finished first; keep the established
                    // session instead of replacing it.
                    context.destroy();
                    return;
                }
            }

            sendRaw(ClientMessage.sessionAck(
                    peerName,
                    Base64.getEncoder().encodeToString(ownEphemeralBytes),
                    Base64.getEncoder().encodeToString(mySignature),
                    Base64.getEncoder().encodeToString(confirmation)));

            listener.onSystem("Handshake response sent to " + peerName
                    + ", waiting for key confirmation");
        } catch (Exception e) {
            listener.onError("HANDSHAKE_FAILED",
                    "Failed to handle INIT_SESSION: " + e.getMessage());
        } finally {
            wipe(sharedSecret);
        }
    }

    /**
     * Handles the case where both peers start a handshake at the same time.
     * The lexicographically smaller username keeps its initiator role; the
     * other side abandons its own attempt and answers as responder. Without
     * this rule the two contexts would overwrite each other.
     */
    private boolean shouldAcceptIncomingHandshake(String peerName) {
        SessionContext existing = sessions.get(peerName);
        if (existing == null || existing.getState() == SessionContext.State.FAILED) {
            return true;
        }
        // A stale context must never block a fresh handshake forever.
        if (existing.isExpired()) {
            existing.destroy();
            sessions.remove(peerName, existing);
            return true;
        }
        if (existing.isReady()) {
            return false;
        }
        if (existing.getState() == SessionContext.State.WAITING_FOR_ACK) {
            if (ownName.compareTo(peerName) < 0) {
                return false;
            }
            existing.destroy();
            sessions.remove(peerName, existing);
            return true;
        }
        // Already waiting for the initiator's confirmation as responder.
        return false;
    }

    private void handleSessionAck(ServerMessage msg) {
        byte[] sharedSecret = null;
        try {
            String peerName = msg.fromClientName;
            SessionContext context = sessions.get(peerName);
            if (context == null || context.getState() != SessionContext.State.WAITING_FOR_ACK) {
                listener.onError("UNEXPECTED_ACK", "SESSION_ACK without pending session from " + peerName);
                return;
            }
            if (msg.confirmation == null || msg.ephemeralPublicKey == null || msg.signature == null) {
                context.failHandshake("Malformed SESSION_ACK");
                return;
            }

            PublicKey peerRsaPublic = keyCache.get(peerName);
            if (peerRsaPublic == null) {
                context.failHandshake("No cached RSA key for verification");
                return;
            }

            PublicKey peerEphemeralPub = EcdhCrypto.publicKeyFromBase64(msg.ephemeralPublicKey);
            byte[] peerEphemeralBytes = peerEphemeralPub.getEncoded();
            byte[] toVerify = SessionCrypto.signingPayload(
                    "ack", peerName, ownName, peerEphemeralBytes);
            byte[] signatureBytes = Base64.getDecoder().decode(msg.signature);

            if (!RsaSignature.verify(toVerify, signatureBytes, peerRsaPublic)) {
                context.failHandshake("Invalid signature");
                listener.onError("BAD_SIGNATURE", "Invalid signature in SESSION_ACK from " + peerName);
                return;
            }

            byte[] ownEphemeralBytes = context.getEphemeralKeyPair().getPublic().getEncoded();
            sharedSecret = EcdhCrypto.computeSharedSecret(
                    context.getEphemeralPrivateKey(), peerEphemeralPub);

            SessionCrypto.DerivedKeys keys = SessionCrypto.derive(
                    sharedSecret, ownName, peerName, ownEphemeralBytes, peerEphemeralBytes);

            byte[] peerConfirmation = Base64.getDecoder().decode(msg.confirmation);
            byte[] ownConfirmation = context.completeAsInitiator(keys, peerConfirmation);

            // Send CONFIRM before waking the waiting sender, so the first DM
            // cannot overtake it on the wire.
            sendRaw(ClientMessage.sessionConfirm(
                    peerName, Base64.getEncoder().encodeToString(ownConfirmation)));
            context.markEstablished();

            listener.onSystem("Session established with " + peerName);
        } catch (Exception e) {
            String peer = msg.fromClientName;
            SessionContext context = peer != null ? sessions.get(peer) : null;
            if (context != null) {
                context.failHandshake("SESSION_ACK processing failed");
            }
            listener.onError("HANDSHAKE_FAILED", "Failed to handle SESSION_ACK: " + e.getMessage());
        } finally {
            wipe(sharedSecret);
        }
    }

    private void handleSessionConfirm(ServerMessage msg) {
        try {
            String peerName = msg.fromClientName;
            SessionContext context = sessions.get(peerName);
            if (context == null) {
                return;
            }
            if (context.getState() == SessionContext.State.READY) {
                return; // duplicate confirmation — harmless
            }
            if (msg.confirmation == null) {
                context.failHandshake("Malformed SESSION_CONFIRM");
                return;
            }
            context.confirmInitiator(Base64.getDecoder().decode(msg.confirmation));
            listener.onSystem("Session established with " + peerName);
        } catch (Exception e) {
            listener.onError("HANDSHAKE_FAILED",
                    "Failed to handle SESSION_CONFIRM: " + e.getMessage());
        }
    }

    private SessionContext getOrEstablishSession(String peerName) throws Exception {
        SessionContext context;
        synchronized (sessionLock) {
            context = sessions.get(peerName);

            if (context != null && context.isReady() && !context.isExpired()) {
                return context;
            }
            if (context != null && (context.isExpired()
                    || context.getState() == SessionContext.State.FAILED)) {
                context.destroy();
                sessions.remove(peerName, context);
                context = null;
            }
            if (context == null) {
                instantiateHandshake(peerName);
                context = sessions.get(peerName);
                if (context == null) {
                    throw new IllegalStateException(
                            "Handshake context disappeared for " + peerName);
                }
            }
        }

        // Wait outside the lock: a peer-initiated handshake needs the lock to
        // install its responder context, and holding it here would deadlock.
        boolean ok = awaitHandshake(context);
        if (!ok) {
            SessionContext replacement = awaitReadyReplacement(peerName);
            if (replacement != null) {
                return replacement;
            }
            synchronized (sessionLock) {
                sessions.remove(peerName, context);
            }
            context.destroy();
            throw new IllegalStateException("Handshake failed with " + peerName);
        }
        return context;
    }

    private boolean awaitHandshake(SessionContext context) {
        try {
            return Boolean.TRUE.equals(context.getHandshakeResult()
                    .get(HANDSHAKE_TIMEOUT_SECONDS, TimeUnit.SECONDS));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * When both peers start a handshake simultaneously this side may abandon
     * its initiator role and answer as responder. Give that replacement
     * handshake a short window to become ready instead of failing the send.
     */
    private SessionContext awaitReadyReplacement(String peerName) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (System.nanoTime() < deadline) {
            SessionContext current = sessions.get(peerName);
            if (current != null && current.isReady() && !current.isExpired()) {
                return current;
            }
            Thread.sleep(50);
        }
        return null;
    }

    private PublicKey requestPublicKey(String peerName) throws Exception {
        PublicKey cached = keyCache.get(peerName);
        if (cached != null) {
            return cached;
        }

        CompletableFuture<PublicKey> future = new CompletableFuture<>();
        CompletableFuture<PublicKey> existing = pendingKeyRequests.putIfAbsent(peerName, future);
        if (existing != null) {
            future = existing;
        } else {
            try {
                sendRaw(ClientMessage.getKey(peerName));
            } catch (Exception e) {
                pendingKeyRequests.remove(peerName, future);
                throw e;
            }
        }

        try {
            return future.get(HANDSHAKE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (Exception e) {
            pendingKeyRequests.remove(peerName, future);
            throw new IllegalStateException("Cannot get RSA key for " + peerName, e);
        }
    }

    private void handleIncoming(ServerMessage msg) {
        if (msg == null || msg.type == null) {
            return;
        }
        switch (msg.type) {
            case DM -> handleDM(msg);
            case DELIVERED -> listener.onDelivered();
            case ERROR -> handleERROR(msg);
            case PUBLIC_KEY -> handlePUBLIC_KEY(msg);
            case SYSTEM -> handleSYSTEM(msg);
            case INIT_SESSION -> handleInitSession(msg);
            case SESSION_ACK -> handleSessionAck(msg);
            case SESSION_CONFIRM -> handleSessionConfirm(msg);
        }
    }

    private void handleSYSTEM(ServerMessage msg) {
        if (joinResult != null && !joinResult.isDone()) {
            joinResult.complete(true);
        }
        listener.onSystem(msg.text);
    }

    private void handleDM(ServerMessage msg) {
        SessionContext session = sessions.get(msg.fromClientName);
        if (session == null || !session.isReady()) {
            listener.onDecryptionFailed(msg.fromClientName);
            return;
        }
        try {
            long expectedSequence = session.nextExpectedSequence();
            String plainText = SessionCrypto.decrypt(
                    msg.e2ePayload,
                    session.getReceiveKey(),
                    msg.fromClientName,
                    ownName,
                    expectedSequence);
            session.markReceived(expectedSequence);
            listener.onMessage(msg.fromClientName, plainText);
        } catch (Exception e) {
            listener.onDecryptionFailed(msg.fromClientName);
        }
    }

    private void handleERROR(ServerMessage msg) {
        if (joinResult != null && !joinResult.isDone()) {
            joinResult.complete(false);
        }
        if (msg.errorCode == ErrorCode.RECIPIENT_OFFLINE) {
            IllegalStateException offline = new IllegalStateException(msg.text);
            pendingKeyRequests.values().forEach(f -> f.completeExceptionally(offline));
            pendingKeyRequests.clear();
        }
        try {
            listener.onError(
                    msg.errorCode != null ? msg.errorCode.name() : "UNKNOWN",
                    msg.text);
        } catch (Exception e) {
            listener.onError(ErrorCode.INTERNAL_ERROR.name(),
                    "[CLIENT][ERROR] error while handling ERROR message from server");
        }
    }

    private void handlePUBLIC_KEY(ServerMessage msg) {
        try {
            PublicKey key = RsaCrypto.publicKeyFromBase64(msg.publicKey);
            keyCache.put(msg.username, key);
            CompletableFuture<PublicKey> future = pendingKeyRequests.remove(msg.username);
            if (future != null) {
                future.complete(key);
            }
        } catch (Exception e) {
            CompletableFuture<PublicKey> future = pendingKeyRequests.remove(msg.username);
            if (future != null) {
                future.completeExceptionally(e);
            }
        }
    }

    private synchronized void sendRaw(ClientMessage msg) throws JsonProcessingException {
        if (out == null) {
            throw new IllegalStateException("Not connected");
        }
        out.println(mapper.writeValueAsString(msg));
        if (out.checkError()) {
            throw new IllegalStateException("Connection lost while sending");
        }
    }

    private synchronized void destroyAllSessions() {
        if (sessionsDestroyed) {
            return;
        }
        sessionsDestroyed = true;
        handshakeExecutor.shutdownNow();
        for (SessionContext session : sessions.values()) {
            try {
                session.destroy();
            } catch (Exception ignored) {
                // best effort
            }
        }
        sessions.clear();
        pendingKeyRequests.values().forEach(f ->
                f.completeExceptionally(new IllegalStateException("Disconnected")));
        pendingKeyRequests.clear();
    }

    private void closeSocketQuietly() {
        try {
            if (sslSocket != null) {
                sslSocket.close();
            }
        } catch (Exception ignored) {
            // best effort
        }
    }

    private static void wipe(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
