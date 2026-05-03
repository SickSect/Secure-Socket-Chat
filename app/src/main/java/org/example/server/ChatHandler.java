package org.example.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.client.ClientMessage;
import org.example.client.CommandType;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.SocketAddress;

public class ChatHandler implements Runnable{

    private final Socket clientSocket;
    private final ChatRoom room;
    public PrintWriter out;
    public BufferedReader in;
    private String clientName = null;
    private final ObjectMapper mapper = new ObjectMapper();

    public ChatHandler(Socket clientSocket, ChatRoom chatRoom) throws IOException {
        this.clientSocket = clientSocket;
        room = chatRoom;
    }

    @Override
    public void run() {
        try{

            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            out = new PrintWriter(clientSocket.getOutputStream(), true);
            System.out.println("[ChatHandler] client connected: " + clientSocket.getRemoteSocketAddress());


            String line;
            clientName = in.readLine();
            System.out.println("[ChatHandler] client username: " + clientName);
            room.joinClient(clientName, this);
            while((line = in.readLine()) != null){
                System.out.println("[ChatHandler] received: " + line);
                ClientMessage msg = mapper.readValue(line, ClientMessage.class);
                if (msg.commandType == CommandType.QUIT) {
                    System.out.println("[ChatHandler] client quit: " + clientName);
                    room.leaveClient(clientName);
                    break;
                }
                else if (msg.commandType == CommandType.SEND_MESSAGE){
                    System.out.println("[ChatHandler] send message: " + clientName);
                    room.sendMessage(msg);
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
