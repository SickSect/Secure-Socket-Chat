package org.ugina.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.ugina.crypto.*;
import org.ugina.crypto.exception.CryptoException;
import org.ugina.crypto.keyStorage.FileBasedKeyStorage;
import org.ugina.crypto.keyStorage.KeyStorage;
import org.ugina.protocol.ClientMessage;
import org.ugina.protocol.ErrorCode;
import org.ugina.protocol.ServerMessage;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.file.Path;
import java.security.*;
import java.util.Base64;
import java.util.concurrent.*;

public class ChatClientCore {
    ChatEventListener listener;

    private final String HOST;
    private final int PORT;
    private final SecretKey PSK_KEY;

    private static final ObjectMapper mapper = new ObjectMapper();
    private static final ConcurrentHashMap<String, PublicKey> keyCache = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, CompletableFuture<PublicKey>> pendingKeyRequests = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, SessionContext> sessions = new ConcurrentHashMap<>();
    private CompletableFuture<Boolean> joinResult;

    private PrivateKey privateKey;

    private BufferedReader in;
    private PrintWriter out;

    private volatile boolean connected = true;
    private volatile boolean sessionsDestroyed = false;
    private Socket socketCache;

    public ChatClientCore(
            ChatEventListener listener,
            String host,
            int port) throws GeneralSecurityException {
        this.listener = listener;
        HOST = host;
        PORT = port;
        PSK_KEY = KeyLoader.getSecretKey();
    }

    /**
     * Подключается к серверу с готовым JWT и ключевой парой.
     *
     * @param jwt     токен полученный через REST-логин
     * @param keyPair RSA-пара пользователя (приватный нужен для handshake)
     * @return true если JOIN успешен
     */
    public boolean connect(String jwt, KeyPair keyPair) throws Exception {
        this.privateKey = keyPair.getPrivate();

        try {
            socketCache = new Socket(HOST, PORT);
            socketCache.setKeepAlive(true);
            in = new BufferedReader(new InputStreamReader(socketCache.getInputStream()));
            out = new PrintWriter(socketCache.getOutputStream(), true);

        } catch (Exception e) {
            System.err.println("[ERROR] Could not connect to server!");
            throw new RuntimeException("[ERROR] Could not connect to server!");
        }
        joinResult = new CompletableFuture<>();
        connected = true;
        startReaderThread();
        sendRaw(ClientMessage.join(jwt));
        try {
            return joinResult.get(10, TimeUnit.SECONDS);
        } catch (Exception e) {
            return false;
        }
    }

    public void disconnect() {
        try {
            if (out != null)
                sendRaw(ClientMessage.quit());
            if (socketCache != null)
                socketCache.close();
        } catch (Exception e) {
            System.err.println("[ERROR] Error while trying to disconnect from server!");
        }finally {
            destroyAllSessions();   // ← затираем ключи при выходе
            connected = false;
        }
    }

    /**
     * Затирает и удаляет все активные сессии.
     * Идемпотентно — повторный вызов безопасен (guard-флаг).
     * Вызывается при отключении от сервера или штатном выходе.
     */
    private synchronized void destroyAllSessions() {
        if (sessionsDestroyed) {
            return;   // уже затёрли — выходим
        }
        sessionsDestroyed = true;

        for (SessionContext session : sessions.values()) {
            try {
                session.destroy();
            } catch (Exception e) {
                // best effort — продолжаем чистить остальные
            }
        }
        sessions.clear();
    }

    public void sendMessage(String recipient, String text) throws Exception {
        if (!connected) {
            listener.onError("DISCONNECTED", "Not connected to server");
            return;
        }
        SessionContext session;
        try{
            session = getOrEstablishSession(recipient);
        }catch (Exception e){
            listener.onError("SESSION_FAILED", "Could not establish session with " + recipient + ": " + e.getMessage());
            return;
        }
        String e2ePayload = AesCrypto.encrypt(text, session.getSessionKey());
        byte[] nonceBytes = new byte[16];
        new SecureRandom().nextBytes(nonceBytes);
        String nonce = Base64.getEncoder().encodeToString(nonceBytes);
        ClientMessage msg = ClientMessage.message(recipient, nonce, e2ePayload);
        sendRaw(msg);
    }

    /**
     * Create thread that reads server responses
     */
    private void startReaderThread() {
        Thread thread = new Thread(() -> {
            try {
                String line;
                while ((line = in.readLine()) != null) {
                    String decoded = AesCrypto.decrypt(line, PSK_KEY);
                    ServerMessage msg = mapper.readValue(decoded, ServerMessage.class);
                    handleIncoming(msg);
                }
                connected = false;
                destroyAllSessions();
                listener.onConnectionLost();
            } catch (Exception ex) {
                connected = false;
                destroyAllSessions();
                listener.onConnectionLost();
            }
        }, "client-reader-thread");
        thread.setDaemon(true);
        thread.start();
    }

    private void instantiateHandshake(String peerName) throws CryptoException, JsonProcessingException {
        PublicKey peerPublicKey = keyCache.get(peerName);
        if (peerPublicKey == null) {
            CompletableFuture<PublicKey> future = new CompletableFuture<>();
            pendingKeyRequests.put(peerName, future);
            try {
                sendRaw(ClientMessage.getKey(peerName));
                peerPublicKey = future.get(10, TimeUnit.SECONDS);
            } catch (Exception e) {
                pendingKeyRequests.remove(peerName);
                throw new RuntimeException("Cannot get RSA key for " + peerName);
            }
        }
        KeyPair ephemeralKeyPair;
        try {
            ephemeralKeyPair = EcdhCrypto.generateKeyPair();
        } catch (CryptoException e) {
            throw new CryptoException("Can not generate ephemeral key pair!", e);
        }
        String ephPubBase64 = EcdhCrypto.publicKeyToBase64(ephemeralKeyPair.getPublic());
        byte[] ephemeralPubBytes = ephemeralKeyPair.getPublic().getEncoded();
        byte[] signature = RsaSignature.sign(ephemeralPubBytes, this.privateKey);
        String signatureBase64 = Base64.getEncoder().encodeToString(signature);
        SessionContext context = new SessionContext(peerName,ephemeralKeyPair);
        sessions.put(peerName, context);
        sendRaw(ClientMessage.initSession(peerName, ephPubBase64, signatureBase64));
    }

    public void handleInitSession(ServerMessage msg){
        new Thread(() -> handleInitSessionAsync(msg), "handshake-handler").start();
    }

    private void handleInitSessionAsync(ServerMessage msg) {
        try{
            String peerName = msg.fromClientName;
            PublicKey peerRsaPublicKey = keyCache.get(peerName);
            if (peerRsaPublicKey == null) {
                CompletableFuture<PublicKey> future = new CompletableFuture<>();
                pendingKeyRequests.put(peerName, future);
                sendRaw(ClientMessage.getKey(peerName));
                peerRsaPublicKey = future.get(10, TimeUnit.SECONDS);
            }
            PublicKey peerEphemeralPub = EcdhCrypto.publicKeyFromBase64(msg.ephemeralPublicKey);
            byte[] peerEphemeralBytes = peerEphemeralPub.getEncoded();
            byte[] signature = Base64.getDecoder().decode(msg.signature);

            if (!RsaSignature.verify(peerEphemeralBytes, signature, peerRsaPublicKey)) {
                listener.onError("BAD_SIGNATURE", "Invalid signature in INIT_SESSION from " + peerName);
                return;
            }
            KeyPair ownEphemeralKeyPair = EcdhCrypto.generateKeyPair();
            byte[] sharedSecret = EcdhCrypto.computeSharedSecret(ownEphemeralKeyPair.getPrivate(), peerEphemeralPub);
            byte[] sessionKeyBytes = HkdfCrypto.derive(sharedSecret, null, "secure-chat-session", 32);

            SessionContext context = new SessionContext(peerName,ownEphemeralKeyPair);
            sessions.put(peerName, context);
            context.completeHandshake(sessionKeyBytes);

            byte[] myEphemeralPubBytes = ownEphemeralKeyPair.getPublic().getEncoded();
            byte[] mySignature = RsaSignature.sign(myEphemeralPubBytes, privateKey);
            String myEphemeralPubBase64 = EcdhCrypto.publicKeyToBase64(ownEphemeralKeyPair.getPublic());
            String mySignatureBase64 = Base64.getEncoder().encodeToString(mySignature);

            // 8. Отправляем SESSION_ACK
            sendRaw(ClientMessage.sessionAck(peerName, myEphemeralPubBase64, mySignatureBase64));

            listener.onSystem("Session established with " + peerName);
        }catch(Exception e){
            listener.onError("HANDSHAKE_FAILED", "Failed to handle INIT_SESSION: " + e.getMessage());
        }
    }

    private void handleSessionAck(ServerMessage msg)
    {
        try {
            String peerName = msg.fromClientName;

            // 1. Достаём ожидающую сессию
            SessionContext context = sessions.get(peerName);
            if (context == null || context.getState() != SessionContext.State.WAITING_FOR_ACK) {
                listener.onError("UNEXPECTED_ACK", "SESSION_ACK without pending session from " + peerName);
                return;
            }

            // 2. Достаём RSA-public собеседника
            PublicKey peerRsaPublic = keyCache.get(peerName);
            if (peerRsaPublic == null) {
                context.failHandshake("No RSA key for verification");
                return;
            }

            // 3. Декодируем эфемерный публичный собеседника
            PublicKey peerEphemeralPub = EcdhCrypto.publicKeyFromBase64(msg.ephemeralPublicKey);
            byte[] peerEphemeralBytes = peerEphemeralPub.getEncoded();
            byte[] signatureBytes = Base64.getDecoder().decode(msg.signature);

            // 4. Проверяем подпись
            if (!RsaSignature.verify(peerEphemeralBytes, signatureBytes, peerRsaPublic)) {
                context.failHandshake("Invalid signature");
                listener.onError("BAD_SIGNATURE", "Invalid signature in SESSION_ACK from " + peerName);
                return;
            }

            // 5. Вычисляем общий секрет используя НАШ эфемерный private и ИХ эфемерный public
            byte[] sharedSecret = EcdhCrypto.computeSharedSecret(
                    context.getEphemeralPrivateKey(), peerEphemeralPub);
            byte[] sessionKeyBytes = HkdfCrypto.derive(sharedSecret, null, "secure-chat-session", 32);

            // 6. Завершаем handshake — наш эфемерный приватный СТИРАЕТСЯ
            context.completeHandshake(sessionKeyBytes);

            listener.onSystem("Session established with " + peerName);

        } catch (Exception e) {
            listener.onError("HANDSHAKE_FAILED", "Failed to handle SESSION_ACK: " + e.getMessage());
        }
    }

    private SessionContext getOrEstablishSession(String peerName) throws Exception {
        SessionContext existing = sessions.get(peerName);
        if (existing != null && existing.isReady() && !existing.isExpired()) {
            return existing;   // готова И не истекла → переиспользуем
        }

        // Сессия истекла — убираем старую перед новым handshake
        if (existing != null && existing.isExpired()) {
            existing.destroy();
            sessions.remove(peerName);
            listener.onSystem("Session with " + peerName + " expired, re-establishing...");
        }

        instantiateHandshake(peerName);
        SessionContext context = sessions.get(peerName);
        boolean ok = context.getHandshakeResult().get(10, TimeUnit.SECONDS);
        if (!ok) {
            throw new RuntimeException("Handshake failed with " + peerName);
        }
        return context;
    }

    /**
     * Acquire decoded server response
     *
     * @param msg - response from server ServerMessage.class
     */
    private void handleIncoming(ServerMessage msg) throws CryptoException {
        switch (msg.type) {
            case DM -> handleDM(msg);
            case DELIVERED -> handleDELIVERED(msg);
            case ERROR -> handleERROR(msg);
            case PUBLIC_KEY -> handlePUBLIC_KEY(msg);
            case SYSTEM -> handleSYSTEM(msg);
            case INIT_SESSION -> handleInitSession(msg);
            case SESSION_ACK -> handleSessionAck(msg);
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
        try{
            String plainText = AesCrypto.decrypt(msg.e2ePayload, session.getSessionKey());
            session.touch();
            listener.onMessage(msg.fromClientName, plainText);
        }catch (Exception e){
            listener.onDecryptionFailed(msg.fromClientName);
        }
    }

    private void handleDELIVERED(ServerMessage msg) {
        try {
            listener.onDelivered();
        } catch (Exception e) {
            listener.onError(ErrorCode.INTERNAL_ERROR.name(), "[CLIENT][ERROR] error while handle DELIVERED message from server");
        }
    }

    private void handleERROR(ServerMessage msg) {
        if (joinResult != null && !joinResult.isDone()){
            joinResult.complete(false);
        }
        try {
            listener.onError(msg.errorCode != null ? msg.errorCode.name() : "UNKNOWN", msg.text);
        } catch (Exception e) {
            listener.onError(ErrorCode.INTERNAL_ERROR.name(), "[CLIENT][ERROR] error while handle ERROR message from server");
        }
    }

    private void handlePUBLIC_KEY(ServerMessage msg) {
        try {
            PublicKey key = RsaCrypto.publicKeyFromBase64(msg.publicKey);
            keyCache.putIfAbsent(msg.username, key);
            CompletableFuture<PublicKey> future = pendingKeyRequests.remove(msg.username);
            if (future != null) {
                future.complete(key);
            }
        } catch (Exception e) {

        }
    }

    private void sendRaw(ClientMessage msg) throws JsonProcessingException, CryptoException {
        String json = mapper.writeValueAsString(msg);
        String encrypted = AesCrypto.encrypt(json, PSK_KEY);
        out.println(encrypted);
    }
}
