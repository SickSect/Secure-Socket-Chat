package org.example.server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ChatServer {
    private static final int PORT = 5000;

    public static void main(String[] args) throws IOException {
        System.out.println("[server] starting on port " + PORT);

        ExecutorService executorService = Executors.newCachedThreadPool();

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("[server] waiting for client...");
            ChatRoom room = new ChatRoom();
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("[server] client connected: " + clientSocket.getRemoteSocketAddress());

                ChatHandler chatHandler = new ChatHandler(clientSocket, room);
                executorService.execute(chatHandler);
            }
        }
    }
}
