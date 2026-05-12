package org.ugina.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.ugina.crypto.Crypto;
import org.ugina.protocol.ClientMessage;
import org.ugina.protocol.CommandType;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class ChatHandler implements Runnable{

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
        try{

            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            out = new PrintWriter(clientSocket.getOutputStream(), true);
            System.out.println("[ChatHandler] client connected: " + clientSocket.getRemoteSocketAddress());


            String line;

            while((line = in.readLine()) != null){
                System.out.println("[ChatHandler] received: " + line);
                String decryptedMsg = Crypto.decrypt(line, secretKey);
                ClientMessage msg = mapper.readValue(decryptedMsg, ClientMessage.class);
                System.out.println("[ChatHandler] received decoded: " + msg.message + " " + msg.clientName +  " " + msg.commandType);
                if (msg.commandType == CommandType.QUIT) {
                    System.out.println("[ChatHandler] client quit: " + clientName);
                    room.leaveClient(clientName);
                    break;
                }
                else if (msg.commandType == CommandType.SEND_MESSAGE){
                    System.out.println("[ChatHandler] send message: " + clientName);
                    room.sendMessage(msg);
                }
                else if (msg.commandType == CommandType.JOIN){
                    System.out.println("[ChatHandler] client username: " + msg.message);
                    room.joinClient(msg.message, this);
                    clientName = msg.message;
                }
            }
        }catch (Exception e){
            System.out.println("[ChatHandler] client disconnected: " + clientSocket.getRemoteSocketAddress());
        }
        finally {
            room.leaveClient(clientName);
        }
    }

}
