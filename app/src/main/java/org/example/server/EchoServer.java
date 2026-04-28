package org.example.server;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;

public class EchoServer {
    private static final int PORT = 5000;

    public static void main(String[] args) throws IOException {
        System.out.println("[server] starting on port " + PORT);

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("[server] waiting for client...");
            try (Socket client = serverSocket.accept();
                 BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));
                 PrintWriter out = new PrintWriter(client.getOutputStream(), true)) {

                System.out.println("[server] client connected: " + client.getRemoteSocketAddress());

                String line;
                while ((line = in.readLine()) != null) {
                    System.out.println("[server] received: " + line);
                    if ("/quit".equals(line)) {
                        out.println("bye");
                        break;
                    }
                    out.println("echo: " + line);
                }
                System.out.println("[server] client disconnected");
            }
        }
    }
}
