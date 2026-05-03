package org.example.server;

import org.example.client.ClientMessage;

import java.util.concurrent.ConcurrentHashMap;

public class ChatRoom {
    private ConcurrentHashMap<String ,ChatHandler> clientHandlers = new ConcurrentHashMap<>();

    public boolean joinClient(String clientName, ChatHandler chatHandler) {
        ChatHandler existing = clientHandlers.putIfAbsent(clientName, chatHandler);
        if (existing != null) {
            System.out.println("[joinClient] name taken: " + clientName);
            return false;
        }
        System.out.println("[joinClient] " + clientName + " joined");
        return true;
    }

    public void leaveClient(String clientName) {
        System.out.println("[leaveClient] client connected: " + clientName);
        clientHandlers.remove(clientName);
    }

    public void sendMessage(ClientMessage message) {
        System.out.println("[sendMessage] from client send: " + message.fromClientName + " to client: " + message.toClientName + " message: " + message.message);
        if (!clientHandlers.containsKey(message.toClientName)) {
            clientHandlers.get(message.fromClientName).out.println("[server] client:" + message.toClientName + " not connected");
            return ;
        }
        String msg = "[" + message.fromClientName + "]: " + message.message;
        clientHandlers.get(message.toClientName).out.println(msg);
        String responseMsg = "[message delivered]";
        clientHandlers.get(message.fromClientName).out.println(responseMsg);
    }

}
