package org.ugina.server;

import lombok.extern.slf4j.Slf4j;
import org.apache.juli.logging.Log;
import org.ugina.auth.AuthProvider;
import org.ugina.crypto.KeyLoader;
import org.ugina.utils.CustomLogger;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Slf4j
public class ChatServer {
    private static final SecretKey key;
    private final int port;
    private final AuthProvider authProvider;

    static {
        try {
            key = KeyLoader.getSecretKey();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public ChatServer(int port, AuthProvider authProvider) {
        this.port = port;
        this.authProvider = authProvider;
    }

    public void start(){
        CustomLogger.logInfo("Start chat server...", ChatServer.class.getName());
        ExecutorService executor = Executors.newCachedThreadPool();
        try(ServerSocket serverSocket = new ServerSocket(this.port)){
            CustomLogger.logInfo("Waiting for client...", ChatServer.class.getName());
            ChatRoom room = new ChatRoom();
            while(true){
                Socket socket = serverSocket.accept();
                CustomLogger.logInfo("Client connected! %s".formatted(socket.getRemoteSocketAddress()), ChatServer.class.getName());
                ChatHandler handler = new ChatHandler(socket, room, key, authProvider);
                executor.execute(handler);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
