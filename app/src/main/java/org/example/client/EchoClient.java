package org.example.client;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.*;
import java.net.Socket;

public class EchoClient {
    private static final String HOST = "localhost";
    private static final int PORT = 5000;
    private static final ObjectMapper mapper = new ObjectMapper();

    public static void main(String[] args) throws IOException {
        try (Socket socket = new Socket(HOST, PORT);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in))) {

            System.out.println("[client] connected to " + HOST + ":" + PORT);
            System.out.println("[client] type messages, /quit to exit");

            Thread reader = new Thread(() -> {
                try{
                    String line;
                    while ((line = in.readLine()) != null){
                        System.out.println("[server]: " + line);
                    }
                }catch (IOException e){
                    System.out.println("[client]: connection lost");
                }
            });
            reader.setDaemon(true);
            reader.start();

            // GET NAME
            System.out.println("[client] Enter your name:");
            String clientName = stdin.readLine();
            out.println(clientName);

            while (true) {
                System.out.println("[client] Enter command: /msg or /quit");
                String cmd = stdin.readLine();
                if (cmd == null || "/quit".equals(cmd)) {
                    ClientMessage quitMsg = new ClientMessage(null, clientName, null, CommandType.QUIT);
                    out.println(mapper.writeValueAsString(quitMsg));
                    break;
                }
                if ("/msg".equals(cmd)) {
                    System.out.println("[client] Enter receiver:");
                    String receiver = stdin.readLine();
                    System.out.println("[client] Enter message:");
                    String text = stdin.readLine();
                    ClientMessage msg = new ClientMessage(receiver, clientName, text, CommandType.SEND_MESSAGE);
                    out.println(mapper.writeValueAsString(msg));
                }
            }
        }
    }
}