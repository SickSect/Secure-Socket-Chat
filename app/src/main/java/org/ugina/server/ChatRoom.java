package org.ugina.server;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.ugina.crypto.Crypto;
import org.ugina.crypto.CryptoException;
import org.ugina.crypto.KeyLoader;
import org.ugina.protocol.*;

import java.security.GeneralSecurityException;
import java.util.concurrent.ConcurrentHashMap;

public class ChatRoom {
    private ConcurrentHashMap<String, ChatHandler> clientHandlers = new ConcurrentHashMap<>();
    //private ConcurrentHashMap<String ,ClientStatus> clientStatuses = new ConcurrentHashMap<>();
    private final ObjectMapper mapper = new ObjectMapper();

    public boolean joinClient(String clientName, ChatHandler chatHandler) throws JsonProcessingException, GeneralSecurityException, CryptoException {
        ChatHandler existing = clientHandlers.putIfAbsent(clientName, chatHandler);
        //ClientStatus status = clientStatuses.get(clientName);
        if (existing != null) {
            System.out.println("[joinClient] name taken: " + clientName);
            return false;
        }
/*        if (status == null) {
            clientStatuses.putIfAbsent(clientName, ClientStatus.ONLINE);
        }else{
            if (status == ClientStatus.BLOCKED){
                ClientMessage clientMessage = new ClientMessage();
                clientMessage.commandType = CommandType.SEND_MESSAGE;
                clientMessage.toClientName = clientName;
                clientMessage.message = "You are blocked!";
                clientMessage.clientName = "System";
                sendMessage(clientMessage, clientName);
                return false;
            }else{
                clientStatuses.replace(clientName, ClientStatus.ONLINE);
            }
        }*/
        System.out.println("[joinClient] " + clientName + " joined");
        return true;
    }

    public void leaveClient(String clientName) {
        System.out.println("[leaveClient] client connected: " + clientName);
        clientHandlers.remove(clientName);
        //clientStatuses.replace(clientName, ClientStatus.OFFLINE);
    }

    private ServerMessage createServerMessage(String fromClientName, String text, ErrorCode errorCode, MessageType type) {
        ServerMessage serverMessage = new ServerMessage();
        serverMessage.fromClientName = fromClientName;
        serverMessage.text = text;
        serverMessage.type = type;
        serverMessage.errorCode = errorCode;
        return serverMessage;
    }

    public void sendMessage(ClientMessage message, String clientName) {
        ChatHandler recipient = clientHandlers.get(message.toClientName);
        ChatHandler sender = clientHandlers.get(clientName);

        if (recipient == null) {
            sendTo(sender, createServerMessage(null, "User offline",
                    ErrorCode.RECIPIENT_OFFLINE, MessageType.ERROR));
            return;
        }

        sendTo(recipient, createServerMessage(clientName, message.message, null, MessageType.DM));
        sendTo(sender, createServerMessage(null, "delivered", null, MessageType.DELIVERED));
    }

    private void sendTo(ChatHandler handler, ServerMessage msg) {
        if (handler == null) return;
        try {
            String json = mapper.writeValueAsString(msg);
            String encrypted = Crypto.encrypt(json, KeyLoader.getSecretKey());
            handler.out.println(encrypted);
        } catch (Exception e) {
            System.err.println("[ChatRoom] send failed: " + e.getMessage());
        }
    }

}
