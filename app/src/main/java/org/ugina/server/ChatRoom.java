package org.ugina.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.ugina.crypto.AesCrypto;
import org.ugina.crypto.KeyLoader;
import org.ugina.protocol.*;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class ChatRoom {
    private ConcurrentHashMap<String, ChatHandler> clientHandlers = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, PublicKey> clientPublicKeys = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> nonces = new ConcurrentHashMap<>();
    private static final long NONCE_TTL_MS = 60_000;

    public ChatRoom() throws GeneralSecurityException {
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor( r -> {
            Thread thread = new Thread( r, "nonce-cleaner" );
            thread.setDaemon( true );
            return thread;
        });
        scheduler.scheduleAtFixedRate(this::cleanupNonces, 1, 1, TimeUnit.MINUTES);
    }

    public boolean forwardHandshake(String toName, String fromName, String ephemeralKey, String signature, boolean isAsk){
        ChatHandler recipient = clientHandlers.get(toName);
        if (recipient == null) return false;
        ServerMessage msg = isAsk ?
                ServerMessage.sessionAsk(fromName, ephemeralKey, signature)
                : ServerMessage.initSession(fromName, ephemeralKey, signature);
        recipient.send(msg);
        return true;
    }

    private void cleanupNonces() {
        long now = System.currentTimeMillis();
        nonces.entrySet().removeIf(e -> e.getValue() < now);
    }

    public boolean joinClient(String clientName, ChatHandler chatHandler, PublicKey key){
        ChatHandler existing = clientHandlers.putIfAbsent(clientName, chatHandler);
        if (existing != null) {
            System.out.println("[joinClient] name taken: " + clientName);
            return false;
        }
        clientPublicKeys.putIfAbsent(clientName, key);
        System.out.println("[joinClient] " + clientName + " joined");
        return true;
    }



    public void leaveClient(String clientName) {
        if (clientName == null) return;
        System.out.println("[leaveClient] " + clientName + " left");
        clientHandlers.remove(clientName);
        clientPublicKeys.remove(clientName);
    }

    public boolean checkAndAddNonce(String nonce){
        long now = System.currentTimeMillis();
        Long previous = nonces.putIfAbsent(nonce, now + NONCE_TTL_MS);
        return previous == null;
    }


    public void sendMessage(ClientMessage clientMessage, String clientName) {
        ChatHandler recipient = clientHandlers.get(clientMessage.toClientName);
        ChatHandler client = clientHandlers.get(clientName);
        if (recipient == null){
            ServerMessage error = new ServerMessage();
            error.type = MessageType.ERROR;
            error.errorCode = ErrorCode.RECIPIENT_OFFLINE;
            error.text = "[ERROR] " + clientMessage.toClientName + " not connected";
            sendTo(client, error);
            return ;
        }

        ServerMessage dm = new ServerMessage();
        dm.type = MessageType.DM;
        dm.e2ePayload = clientMessage.e2ePayload;
        dm.fromClientName = clientName;
        sendTo(recipient, dm);

        ServerMessage approve = new ServerMessage();
        approve.type = MessageType.DELIVERED;
        sendTo(client, approve);
    }

    private void sendTo(ChatHandler handler, ServerMessage msg) {
        if (handler == null) return;
        try {
            handler.send(msg);
        } catch (Exception e) {
            System.err.println("[ChatRoom] send failed: " + e.getMessage());
        }
    }

    public boolean registerKey(String clientName, PublicKey key){
        return clientPublicKeys.putIfAbsent(clientName, key) == null;
    }

    public PublicKey getPublicKey(String clientName){
        return clientPublicKeys.get(clientName);
    }

    public void removeKey(String clientName){
        clientPublicKeys.remove(clientName);
    }
}
