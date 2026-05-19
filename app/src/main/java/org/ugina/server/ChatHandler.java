package org.ugina.server;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.ugina.crypto.AesCrypto;
import org.ugina.crypto.RsaCrypto;
import org.ugina.protocol.*;

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
    public PrintWriter out;
    public BufferedReader in;
    private String clientName = null;
    private final ObjectMapper mapper = new ObjectMapper();
    private final SecretKey secretKey;


    public ChatHandler(Socket clientSocket, ChatRoom chatRoom, SecretKey secretKey) throws IOException {
        this.clientSocket = clientSocket;
        this.secretKey = secretKey;
        room = chatRoom;
    }

    @Override
    public void run() {
        try {

            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            out = new PrintWriter(clientSocket.getOutputStream(), true);
            System.out.println("[ChatHandler] client connected: " + clientSocket.getRemoteSocketAddress());


            String line;

            while ((line = in.readLine()) != null) {
                String decryptedMsg = AesCrypto.decrypt(line, secretKey);
                ClientMessage msg = mapper.readValue(decryptedMsg, ClientMessage.class);
                if (clientName == null && msg.commandType != CommandType.JOIN) {
                    System.err.println("[ChatHandler] protocol error: first message must be JOIN");
                    return;
                }
                switch (msg.commandType) {
                    case JOIN -> {
                        PublicKey pk;
                        try {
                            pk = RsaCrypto.publicKeyFromBase64(msg.publicKey);
                        } catch (Exception ex) {
                            System.err.println("[ChatHandler] crypto error: [INVALID KEY FROM " + msg.username + "] " + ex.getMessage());
                            break;
                        }
                        clientName = msg.username;
                        System.out.println("[ChatHandler] client connected: " + msg.username);
                        room.joinClient(msg.username, this, pk);
                    }
                    case QUIT -> {
                        System.out.println("[ChatHandler] client quit: " + clientName);
                        return;
                    }
                    case SEND_MESSAGE -> {
                        ErrorCode errorCode = ServerHandlerService.validateSendMessage(msg, room);
                        if (errorCode != null) {
                            ServerMessage serverMessage = new ServerMessage();
                            serverMessage.type = MessageType.ERROR;
                            serverMessage.errorCode = errorCode;
                            serverMessage.text = errorCode == ErrorCode.EXPIRED ? "Message expired" : "Replay detected";
                            send(serverMessage);
                        } else {
                            room.sendMessage(msg, clientName);
                        }
                    }
                    case GET_KEY -> {
                        PublicKey key = room.getPublicKey(msg.toClientName);
                        ServerMessage serverMessage = new ServerMessage();
                        if (key == null) {
                            serverMessage.errorCode = ErrorCode.RECIPIENT_OFFLINE;
                            serverMessage.type = MessageType.ERROR;
                            serverMessage.text = "User: " + msg.toClientName + " not found";
                        } else {
                            serverMessage.type = MessageType.PUBLIC_KEY;
                            serverMessage.username = msg.toClientName;
                            serverMessage.publicKey = RsaCrypto.publicKeyToBase64(key);
                        }
                        System.out.println("[ChatHandler] get key: " + clientName);
                        send(serverMessage);
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("[ChatHandler] client disconnected: " + clientSocket.getRemoteSocketAddress());
        } finally {
            room.leaveClient(clientName);
        }
    }

    public void send(ServerMessage msg) {
        try {
            String json = mapper.writeValueAsString(msg);
            String encrypted = AesCrypto.encrypt(json, secretKey);
            out.println(encrypted);
        } catch (Exception e) {
            System.err.println("[ChatHandler] send failed: " + e.getMessage());
        }
    }

}
