package org.ugina.server;

import lombok.extern.slf4j.Slf4j;
import org.apache.juli.logging.Log;
import org.ugina.auth.AuthProvider;
import org.ugina.crypto.KeyLoader;
import org.ugina.utils.CustomLogger;

import javax.crypto.SecretKey;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
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

    public void start() throws Exception {
        CustomLogger.logInfo("Start chat server...", ChatServer.class.getName());
        ExecutorService executor = null;

        Path keystorePath = Path.of("certs/server-keystore.p12");
        char[] keystorePassword = "changeit".toCharArray();

        SSLContext sslContext = TlsServerContextFactory.createSSLContext(keystorePath, keystorePassword);
        SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(port);
        serverSocket.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
        try{
            executor = Executors.newCachedThreadPool();
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
        } finally {
            if (executor != null)
                executor.shutdown();
        }
    }
}
