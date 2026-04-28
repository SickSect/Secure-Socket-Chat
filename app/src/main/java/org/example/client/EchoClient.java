package org.example.client;

import java.io.*;
import java.net.Socket;

public class EchoClient {
    private static final String HOST = "localhost";
    private static final int PORT = 5000;

    public static void main(String[] args) throws IOException {
        try (Socket socket = new Socket(HOST, PORT);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in))) {

            System.out.println("[client] connected to " + HOST + ":" + PORT);
            System.out.println("[client] type messages, /quit to exit");

            String userInput;
            while ((userInput = stdin.readLine()) != null) {
                out.println(userInput);
                String response = in.readLine();
                if (response == null) break;
                System.out.println("[server says] " + response);
                if ("/quit".equals(userInput)) break;
            }
        }
    }
}