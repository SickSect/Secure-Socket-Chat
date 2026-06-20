package org.ugina.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.ugina.auth.AuthProvider;
import org.ugina.auth.UserPrincipal;
import org.ugina.auth.exceptions.InvalidTokenException;
import org.ugina.crypto.AesCrypto;
import org.ugina.crypto.RsaCrypto;
import org.ugina.protocol.*;
import org.ugina.utils.CustomLogger;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.PublicKey;

public class ChatHandler implements Runnable {

    private final Socket clientSocket;
    private final ChatRoom room;
    private final SecretKey pskKey;
    private final ObjectMapper mapper = new ObjectMapper();
    private final AuthProvider authProvider;
    private PrintWriter out;
    private BufferedReader in;
    private String clientName = null;

    public ChatHandler(Socket clientSocket, ChatRoom room, SecretKey pskKey, AuthProvider authProvider) {
        this.clientSocket = clientSocket;
        this.room = room;
        this.pskKey = pskKey;
        this.authProvider = authProvider;
    }

    @Override
    public void run() {
        try {
            clientSocket.setKeepAlive(true);
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            out = new PrintWriter(clientSocket.getOutputStream(), true);
            System.out.println("[ChatHandler] client connected: " + clientSocket.getRemoteSocketAddress());

            String line;
            while ((line = in.readLine()) != null) {
                String decrypted = AesCrypto.decrypt(line, pskKey);
                ClientMessage msg = mapper.readValue(decrypted, ClientMessage.class);

                if (clientName == null && msg.commandType != CommandType.JOIN) {
                    System.err.println("[ChatHandler] protocol error: first message must be JOIN");
                    return;
                }

                switch (msg.commandType) {
                    case JOIN -> handleJoin(msg);
                    case SEND_MESSAGE -> handleSendMessage(msg);
                    case GET_KEY -> handleGetKey(msg);
                    case INIT_SESSION -> handleInitSession(msg);
                    case SESSION_ACK -> handleSessionAck(msg);
                    case QUIT -> {
                        System.out.println("[ChatHandler] client quit: " + clientName);
                        return;
                    }
                }
            }
        } catch (Exception e) {
            CustomLogger.logInfo("client disconnected:" + clientSocket.getRemoteSocketAddress(), ChatHandler.class.getName());
        } finally {
            room.leaveClient(clientName);
        }
    }

    private void handleJoin(ClientMessage msg) {
        UserPrincipal principal;
        try{
            principal = authProvider.validate(msg.jwt);
        }catch (InvalidTokenException ex){
            CustomLogger.logInfo("Invalid or expired token", ChatHandler.class.getName());
            send(ServerMessage.error(ErrorCode.INVALID_TOKEN, "Invalid or expired token"));
            return;
        }
        PublicKey pk;
        try {
            pk = RsaCrypto.publicKeyFromBase64(principal.publicKey());
        } catch (Exception e) {
            CustomLogger.logInfo("Invalid public key", ChatHandler.class.getName());
            send(ServerMessage.error(ErrorCode.INVALID_PUBLIC_KEY, "Invalid public key"));
            return;
        }
        boolean joined = room.joinClient(principal.username(), this, pk);
        if (!joined) {
            send(ServerMessage.error(ErrorCode.NAME_TAKEN, principal.username() + " is already in use"));
            return;
        }
        clientName = principal.username();
        send(ServerMessage.system("Welcome, " + principal.username() + "!"));
        CustomLogger.logInfo("joined: " + principal.username(), ChatHandler.class.getName());
    }

    private void handleSendMessage(ClientMessage msg) throws IOException {
        ErrorCode error = ServerHandlerService.validateSendMessage(msg, room);
        if (error != null) {
            String text = error == ErrorCode.EXPIRED ? "Message expired" : "Replay detected";
            send(ServerMessage.error(error, text));
            return;
        }
        room.sendMessage(msg, clientName);
    }

    private void handleGetKey(ClientMessage msg) {
        PublicKey key = room.getPublicKey(msg.toClientName);
        if (key == null) {
            send(ServerMessage.error(ErrorCode.RECIPIENT_OFFLINE,
                    "User " + msg.toClientName + " not found"));
            return;
        }
        send(ServerMessage.publicKey(msg.toClientName, RsaCrypto.publicKeyToBase64(key)));
        System.out.println("[ChatHandler] sent public key of " + msg.toClientName + " to " + clientName);
    }

    public void send(ServerMessage msg) {
        try {
            String json = mapper.writeValueAsString(msg);
            String encrypted = AesCrypto.encrypt(json, pskKey);
            out.println(encrypted);
        } catch (Exception e) {
            System.err.println("[ChatHandler] send failed: " + e.getMessage());
        }
    }

    private void handleInitSession(ClientMessage msg) {
        boolean forwarded = room.forwardHandshake(msg.toClientName, clientName, msg.ephemeralPublicKey, msg.signature, false);
        if (!forwarded)
            send(ServerMessage.error(ErrorCode.RECIPIENT_OFFLINE, "User " + msg.toClientName + " is not connected"));
        System.out.println("[ChatHandler] forwarded INIT_SESSION from " + clientName + " to " + msg.toClientName);
    }

    private void handleSessionAck(ClientMessage msg) {
        boolean forwarded = room.forwardHandshake(msg.toClientName, clientName, msg.ephemeralPublicKey, msg.signature, true);
        if (!forwarded)
            send(ServerMessage.error(ErrorCode.RECIPIENT_OFFLINE, "User " + msg.toClientName + " is not connected"));
        System.out.println("[ChatHandler] forwarded SESSION_ACK from " + clientName + " to " + msg.toClientName);
    }
}