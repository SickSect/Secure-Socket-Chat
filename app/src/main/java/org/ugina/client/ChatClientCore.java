package org.ugina.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.ugina.crypto.AesCrypto;
import org.ugina.crypto.CryptoException;
import org.ugina.crypto.HybridCrypto;
import org.ugina.crypto.RsaCrypto;
import org.ugina.protocol.ClientMessage;
import org.ugina.protocol.ErrorCode;
import org.ugina.protocol.ServerMessage;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class ChatClientCore {
    ChatEventListener listener;

    private final String HOST;
    private final int PORT;
    private final SecretKey PSK_KEY;
    private static final ObjectMapper mapper = new ObjectMapper();
    private static final ConcurrentHashMap<String, PublicKey> keyCache = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, CompletableFuture<PublicKey>> pendingKeyRequests = new ConcurrentHashMap<>();

    private PublicKey publicKey;
    private PrivateKey privateKey;

    private BufferedReader in;
    private PrintWriter out;
    private BufferedReader stdin;

    private Socket socketCache;

    public ChatClientCore(
            ChatEventListener listener,
            String host,
            int port,
            SecretKey pskKey) {
        this.listener = listener;
        HOST = host;
        PORT = port;
        PSK_KEY = pskKey;
    }

    /**
     * Acquire username and create socket connection with server
     *
     * @param username - client username
     */
    public void connect(String username) throws CryptoException, JsonProcessingException {
        KeyPair keyPair;
        try {
            keyPair = RsaCrypto.generateKeyPair();
        } catch (Exception e) {
            System.err.println("[ERROR] Could not generate RSA keys!");
            throw new RuntimeException("[ERROR] Could not generate RSA keys!");
        }
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();

        try (Socket socket = new Socket(HOST, PORT)) {
            socketCache = socket;
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(socket.getOutputStream(), true);
            stdin = new BufferedReader(new InputStreamReader(System.in));

        } catch (Exception e) {
            System.err.println("[ERROR] Could not connect to server!");
            throw new RuntimeException("[ERROR] Could not connect to server!");
        }
        startReaderThread();
        sendRaw(ClientMessage.join(username, publicKey));
    }

    public void disconnect() {
        try {
            if (out != null)
                sendRaw(ClientMessage.quit());
            if (socketCache != null)
                socketCache.close();
        } catch (Exception e) {
            System.err.println("[ERROR] Error while trying to disconnect from server!");
        }
    }

    public void sendMessage(String recipient, String text) throws Exception {
        PublicKey clientPublicKey = keyCache.get(recipient);
        if (clientPublicKey == null) {
            CompletableFuture<PublicKey> future = new CompletableFuture<>();
            pendingKeyRequests.put(recipient, future);
            sendRaw(ClientMessage.getKey(recipient));
            try {
                clientPublicKey = future.get(10, TimeUnit.SECONDS);
            } catch (Exception e) {
                pendingKeyRequests.remove(recipient);
                listener.onError("KEY_TIMEOUT", "Could not find public key for " + recipient + "!");
                return;
            }
        }

        String e2ePayload = HybridCrypto.encrypt(text, clientPublicKey);
        byte[] nonce = new byte[16];
        new SecureRandom().nextBytes(nonce);

        ClientMessage msg = ClientMessage.message(recipient, Base64.getEncoder().encodeToString(nonce), e2ePayload);
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
            } catch (Exception ex) {
                System.err.println("[ERROR][startReaderThread] Error while reading server message!");
            }
        }, "client-reader-thread");
        thread.setDaemon(true);
        thread.start();
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
            case SYSTEM -> System.out.println("[SYSTEM] " + msg);
        }
    }

    private void handleDM(ServerMessage msg) {
        try {
            String plainText = HybridCrypto.decrypt(msg.e2ePayload, privateKey);
            listener.onMessage(msg.fromClientName, plainText);
        } catch (CryptoException e) {
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
