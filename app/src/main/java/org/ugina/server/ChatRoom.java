package org.ugina.server;

import org.ugina.protocol.ClientMessage;
import org.ugina.protocol.ServerMessage;

import java.security.PublicKey;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Registry of connected clients plus a small replay cache.
 *
 * <p>The room no longer holds any application-layer key: all client/server
 * traffic is protected by TLS. Message contents are end-to-end encrypted by
 * the clients and the server only forwards opaque payloads.</p>
 */
public class ChatRoom {

    private static final long NONCE_TTL_MS = 60_000;
    private static final int MAX_NONCES = 100_000;

    private final ConcurrentHashMap<String, ChatHandler> clientHandlers = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, PublicKey> clientPublicKeys = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> nonces = new ConcurrentHashMap<>();

    public ChatRoom() {
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "nonce-cleaner");
            thread.setDaemon(true);
            return thread;
        });
        scheduler.scheduleAtFixedRate(this::cleanupNonces, 1, 1, TimeUnit.MINUTES);
    }

    public boolean joinClient(String clientName, ChatHandler chatHandler, PublicKey key) {
        ChatHandler existing = clientHandlers.putIfAbsent(clientName, chatHandler);
        if (existing != null) {
            return false;
        }
        clientPublicKeys.put(clientName, key);
        return true;
    }

    /**
     * Removes the connection only if it is still the one registered for this
     * username. This prevents a stale handler from evicting a newer session.
     */
    public void leaveClient(String clientName, ChatHandler handler) {
        if (clientName == null || handler == null) {
            return;
        }
        boolean removed = clientHandlers.remove(clientName, handler);
        if (removed) {
            clientPublicKeys.computeIfPresent(clientName,
                    (name, key) -> clientHandlers.containsKey(name) ? key : null);
        }
    }

    /**
     * Replay protection is scoped to the sender, so two clients may use the
     * same random nonce without one of them being rejected.
     */
    public boolean checkAndAddNonce(String sender, String nonce) {
        if (sender == null || nonce == null) {
            return false;
        }
        if (nonces.size() >= MAX_NONCES) {
            cleanupNonces();
            if (nonces.size() >= MAX_NONCES) {
                nonces.clear();
            }
        }
        long now = System.currentTimeMillis();
        Long previous = nonces.putIfAbsent(sender + ':' + nonce, now + NONCE_TTL_MS);
        return previous == null;
    }

    private void cleanupNonces() {
        long now = System.currentTimeMillis();
        nonces.entrySet().removeIf(e -> e.getValue() < now);
    }

    public boolean forwardMessage(ClientMessage message, String fromName) {
        ChatHandler recipient = clientHandlers.get(message.toClientName);
        if (recipient == null) {
            return false;
        }
        recipient.send(ServerMessage.dm(fromName, message.e2ePayload));
        return true;
    }

    public boolean forwardInit(String toName, String fromName, String ephemeralKey, String signature) {
        ChatHandler recipient = clientHandlers.get(toName);
        if (recipient == null) {
            return false;
        }
        recipient.send(ServerMessage.initSession(fromName, ephemeralKey, signature));
        return true;
    }

    public boolean forwardAck(
            String toName,
            String fromName,
            String ephemeralKey,
            String signature,
            String confirmation
    ) {
        ChatHandler recipient = clientHandlers.get(toName);
        if (recipient == null) {
            return false;
        }
        recipient.send(ServerMessage.sessionAck(fromName, ephemeralKey, signature, confirmation));
        return true;
    }

    public boolean forwardConfirm(String toName, String fromName, String confirmation) {
        ChatHandler recipient = clientHandlers.get(toName);
        if (recipient == null) {
            return false;
        }
        recipient.send(ServerMessage.sessionConfirm(fromName, confirmation));
        return true;
    }

    public PublicKey getPublicKey(String clientName) {
        return clientPublicKeys.get(clientName);
    }
}
