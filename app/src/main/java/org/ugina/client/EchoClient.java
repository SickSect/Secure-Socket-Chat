package org.ugina.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.ugina.protocol.ClientMessage;
import org.ugina.protocol.CommandType;

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
            ClientMessage joinMessage = new ClientMessage();
            joinMessage.commandType = CommandType.JOIN;
            joinMessage.clientName = clientName;
            joinMessage.message = clientName;
            out.println(ClientCipherService.encodeMessage(joinMessage));

            while (true) {
                System.out.println("[client] Enter command: /msg or /quit");
                String cmd = stdin.readLine();
                if (cmd == null || "/quit".equals(cmd)) {
                    ClientMessage quitMsg = new ClientMessage();
                    quitMsg.commandType = CommandType.QUIT;
                    quitMsg.clientName = clientName;
                    quitMsg.toClientName = null;
                    quitMsg.message = null;
                    out.println(ClientCipherService.encodeMessage(quitMsg));
                    break;
                }
                if ("/msg".equals(cmd)) {
                    System.out.println("[client] Enter receiver:");
                    String receiver = stdin.readLine();
                    System.out.println("[client] Enter message:");
                    String text = stdin.readLine();
                    ClientMessage msg = new ClientMessage();
                    msg.clientName = clientName;
                    msg.toClientName = receiver;
                    msg.message = text;
                    msg.commandType = CommandType.SEND_MESSAGE;
                    out.println(ClientCipherService.encodeMessage(msg));
                }
            }
        }
    }
}