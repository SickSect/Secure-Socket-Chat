package org.ugina.server;

import org.ugina.crypto.KeyLoader;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ChatServer {
    private static final int PORT = 5000;
    private static final SecretKey key;

    static {
        try {
            key = KeyLoader.getSecretKey();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        System.out.println("[server] starting on port " + PORT);

        ExecutorService executorService = Executors.newCachedThreadPool();
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("[server] waiting for client...");
            ChatRoom room = new ChatRoom();
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("[server] client connected: " + clientSocket.getRemoteSocketAddress());

                ChatHandler chatHandler = new ChatHandler(clientSocket, room, key);
                executorService.execute(chatHandler);
            }
        }
    }
}
