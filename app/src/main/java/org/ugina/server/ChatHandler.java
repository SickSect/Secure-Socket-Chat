package org.ugina.server;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.ugina.auth.AuthProvider;
import org.ugina.auth.UserPrincipal;
import org.ugina.auth.exceptions.InvalidTokenException;
import org.ugina.crypto.RsaCrypto;
import org.ugina.protocol.ClientMessage;
import org.ugina.protocol.CommandType;
import org.ugina.protocol.ErrorCode;
import org.ugina.protocol.ServerMessage;
import org.ugina.utils.CustomLogger;
import org.ugina.utils.FrameReader;
import org.ugina.utils.UsernamePolicy;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

/**
 * Handles one TLS connection.
 *
 * <p>No application-layer encryption happens here on purpose: the socket is
 * already protected by TLS 1.3 and the message body is end-to-end encrypted by
 * the two clients. The server only validates routing metadata and forwards the
 * opaque E2E payload.</p>
 */
public class ChatHandler implements Runnable {

    private static final int MAX_FRAME_CHARS = 96 * 1024;
    private static final int IDLE_TIMEOUT_MS = 30 * 60 * 1000;

    /** Simple per-connection flood guard: 60 commands per 10 seconds. */
    private static final int COMMAND_LIMIT = 60;
    private static final long COMMAND_WINDOW_NANOS = 10_000_000_000L;

    private final Socket clientSocket;
    private final ChatRoom room;
    private final AuthProvider authProvider;
    private final ObjectMapper mapper = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private PrintWriter out;
    private BufferedReader in;
    private String clientName;

    private long windowStartedAt = System.nanoTime();
    private int commandsInWindow;

    public ChatHandler(Socket clientSocket, ChatRoom room, AuthProvider authProvider) {
        this.clientSocket = clientSocket;
        this.room = room;
        this.authProvider = authProvider;
    }

    @Override
    public void run() {
        try {
            clientSocket.setKeepAlive(true);
            clientSocket.setTcpNoDelay(true);
            clientSocket.setSoTimeout(IDLE_TIMEOUT_MS);
            in = new BufferedReader(new InputStreamReader(
                    clientSocket.getInputStream(), StandardCharsets.UTF_8));
            out = new PrintWriter(new OutputStreamWriter(
                    clientSocket.getOutputStream(), StandardCharsets.UTF_8), true);

            String line;
            while ((line = FrameReader.readLine(in, MAX_FRAME_CHARS)) != null) {
                if (!allowCommand()) {
                    send(ServerMessage.error(ErrorCode.RATE_LIMITED, "Too many commands"));
                    return;
                }
                handleLine(line);
                if (clientSocket.isClosed()) {
                    return;
                }
            }
        } catch (SocketTimeoutException e) {
            CustomLogger.logInfo("idle timeout: " + describePeer(), ChatHandler.class.getName());
        } catch (Exception e) {
            CustomLogger.logInfo("client disconnected: " + describePeer(),
                    ChatHandler.class.getName());
        } finally {
            room.leaveClient(clientName, this);
            closeQuietly();
        }
    }

    private void handleLine(String line) {
        if (line.isBlank()) {
            return;
        }
        ClientMessage msg;
        try {
            msg = mapper.readValue(line, ClientMessage.class);
        } catch (Exception e) {
            send(ServerMessage.error(ErrorCode.INVALID_FORMAT, "Malformed JSON"));
            return;
        }
        if (msg.commandType == null) {
            send(ServerMessage.error(ErrorCode.INVALID_FORMAT, "Missing command type"));
            return;
        }
        if (clientName == null && msg.commandType != CommandType.JOIN) {
            send(ServerMessage.error(ErrorCode.INVALID_TOKEN, "JOIN required first"));
            closeQuietly();
            return;
        }

        switch (msg.commandType) {
            case JOIN -> {
                if (!handleJoin(msg)) {
                    closeQuietly();
                }
            }
            case SEND_MESSAGE -> handleSendMessage(msg);
            case GET_KEY -> handleGetKey(msg);
            case INIT_SESSION -> handleInitSession(msg);
            case SESSION_ACK -> handleSessionAck(msg);
            case SESSION_CONFIRM -> handleSessionConfirm(msg);
            case QUIT -> closeQuietly();
        }
    }

    private boolean handleJoin(ClientMessage msg) {
        if (clientName != null) {
            send(ServerMessage.error(ErrorCode.INVALID_FORMAT, "Already joined"));
            return false;
        }
        if (msg.jwt == null || msg.jwt.isBlank()) {
            send(ServerMessage.error(ErrorCode.INVALID_TOKEN, "Invalid or expired token"));
            return false;
        }

        UserPrincipal principal;
        try {
            principal = authProvider.validate(msg.jwt);
        } catch (InvalidTokenException e) {
            send(ServerMessage.error(ErrorCode.INVALID_TOKEN, "Invalid or expired token"));
            return false;
        }
        if (principal == null || !UsernamePolicy.isValid(principal.username())) {
            send(ServerMessage.error(ErrorCode.INVALID_TOKEN, "Invalid or expired token"));
            return false;
        }

        PublicKey publicKey;
        try {
            publicKey = RsaCrypto.publicKeyFromBase64(principal.publicKey());
        } catch (Exception e) {
            send(ServerMessage.error(ErrorCode.INVALID_PUBLIC_KEY, "Invalid public key"));
            return false;
        }

        if (!room.joinClient(principal.username(), this, publicKey)) {
            send(ServerMessage.error(ErrorCode.NAME_TAKEN,
                    principal.username() + " is already in use"));
            return false;
        }
        clientName = principal.username();
        send(ServerMessage.system("Welcome, " + clientName + "!"));
        CustomLogger.logInfo("joined: " + clientName, ChatHandler.class.getName());
        return true;
    }

    private void handleSendMessage(ClientMessage msg) {
        ErrorCode error = ServerHandlerService.validateSendMessage(msg, room, clientName);
        if (error != null) {
            send(ServerMessage.error(error, errorText(error)));
            return;
        }
        if (msg.toClientName.equals(clientName)) {
            send(ServerMessage.error(ErrorCode.INVALID_FORMAT, "Cannot send a message to yourself"));
            return;
        }
        if (!room.forwardMessage(msg, clientName)) {
            send(ServerMessage.error(ErrorCode.RECIPIENT_OFFLINE,
                    msg.toClientName + " is not connected"));
            return;
        }
        send(ServerMessage.delivered());
    }

    private void handleGetKey(ClientMessage msg) {
        if (!UsernamePolicy.isValid(msg.toClientName)) {
            send(ServerMessage.error(ErrorCode.INVALID_FORMAT, "Invalid recipient"));
            return;
        }
        PublicKey key = room.getPublicKey(msg.toClientName);
        if (key == null) {
            send(ServerMessage.error(ErrorCode.RECIPIENT_OFFLINE,
                    "User " + msg.toClientName + " not found"));
            return;
        }
        send(ServerMessage.publicKey(msg.toClientName, RsaCrypto.publicKeyToBase64(key)));
    }

    private void handleInitSession(ClientMessage msg) {
        if (!ServerHandlerService.isValidHandshake(msg, false)
                || msg.toClientName.equals(clientName)) {
            send(ServerMessage.error(ErrorCode.INVALID_FORMAT, "Invalid handshake"));
            return;
        }
        if (!room.forwardInit(msg.toClientName, clientName,
                msg.ephemeralPublicKey, msg.signature)) {
            send(ServerMessage.error(ErrorCode.RECIPIENT_OFFLINE,
                    msg.toClientName + " is not connected"));
        }
    }

    private void handleSessionAck(ClientMessage msg) {
        if (!ServerHandlerService.isValidHandshake(msg, true)
                || msg.toClientName.equals(clientName)) {
            send(ServerMessage.error(ErrorCode.INVALID_FORMAT, "Invalid handshake"));
            return;
        }
        if (!room.forwardAck(msg.toClientName, clientName,
                msg.ephemeralPublicKey, msg.signature, msg.confirmation)) {
            send(ServerMessage.error(ErrorCode.RECIPIENT_OFFLINE,
                    msg.toClientName + " is not connected"));
        }
    }

    private void handleSessionConfirm(ClientMessage msg) {
        if (!ServerHandlerService.isValidConfirmation(msg)
                || msg.toClientName.equals(clientName)) {
            send(ServerMessage.error(ErrorCode.INVALID_FORMAT, "Invalid confirmation"));
            return;
        }
        if (!room.forwardConfirm(msg.toClientName, clientName, msg.confirmation)) {
            send(ServerMessage.error(ErrorCode.RECIPIENT_OFFLINE,
                    msg.toClientName + " is not connected"));
        }
    }

    public void send(ServerMessage msg) {
        PrintWriter writer = out;
        if (writer == null) {
            return;
        }
        try {
            String json = mapper.writeValueAsString(msg);
            synchronized (writer) {
                writer.println(json);
            }
        } catch (Exception e) {
            CustomLogger.logInfo("send failed for " + describePeer(),
                    ChatHandler.class.getName());
        }
    }

    private boolean allowCommand() {
        long now = System.nanoTime();
        if (now - windowStartedAt >= COMMAND_WINDOW_NANOS) {
            windowStartedAt = now;
            commandsInWindow = 0;
        }
        return ++commandsInWindow <= COMMAND_LIMIT;
    }

    private static String errorText(ErrorCode error) {
        return switch (error) {
            case EXPIRED -> "Message expired";
            case REPLAY -> "Replay detected";
            case RATE_LIMITED -> "Too many messages";
            default -> "Invalid message";
        };
    }

    private String describePeer() {
        if (clientName != null) {
            return clientName;
        }
        return String.valueOf(clientSocket.getRemoteSocketAddress());
    }

    private void closeQuietly() {
        try {
            clientSocket.close();
        } catch (Exception ignored) {
            // best effort
        }
    }
}
