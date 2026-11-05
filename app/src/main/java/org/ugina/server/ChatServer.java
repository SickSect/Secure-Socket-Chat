package org.ugina.server;

import lombok.extern.slf4j.Slf4j;
import org.ugina.auth.AuthProvider;
import org.ugina.config.ChatTlsConfig;
import org.ugina.utils.CustomLogger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.net.Socket;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * TLS-only chat server. All connections are accepted on a bounded thread pool
 * so a flood of clients cannot exhaust the JVM thread/memory budget.
 */
@Slf4j
public class ChatServer {

    private static final int CORE_POOL_SIZE = 8;
    private static final int MAX_POOL_SIZE = 64;
    private static final int QUEUE_CAPACITY = 256;
    private static final long KEEP_ALIVE_SECONDS = 60;

    private final int port;
    private final AuthProvider authProvider;
    private final ChatTlsConfig tlsConfig;

    public ChatServer(int port, AuthProvider authProvider, ChatTlsConfig tlsConfig) {
        this.port = port;
        this.authProvider = authProvider;
        this.tlsConfig = tlsConfig;
    }

    public void start() throws Exception {
        CustomLogger.logInfo("Starting chat server on port " + port,
                ChatServer.class.getName());

        SSLContext sslContext = TlsServerContextFactory.createSSLContext(tlsConfig);
        SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(port);
        serverSocket.setReuseAddress(true);
        serverSocket.setEnabledProtocols(new String[]{"TLSv1.3"});
        serverSocket.setNeedClientAuth(false);

        ThreadPoolExecutor executor = new ThreadPoolExecutor(
                CORE_POOL_SIZE,
                MAX_POOL_SIZE,
                KEEP_ALIVE_SECONDS,
                TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(QUEUE_CAPACITY),
                runnable -> {
                    Thread thread = new Thread(runnable, "chat-client");
                    thread.setDaemon(true);
                    return thread;
                },
                new ThreadPoolExecutor.AbortPolicy());

        ChatRoom room = new ChatRoom();
        CustomLogger.logInfo("Waiting for TLS clients...", ChatServer.class.getName());

        try (serverSocket) {
            while (!Thread.currentThread().isInterrupted()) {
                Socket socket = serverSocket.accept();
                try {
                    executor.execute(new ChatHandler(socket, room, authProvider));
                } catch (RejectedExecutionException e) {
                    log.warn("Server is at capacity, rejecting connection from {}",
                            socket.getRemoteSocketAddress());
                    closeQuietly(socket);
                }
            }
        } finally {
            executor.shutdownNow();
        }
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (Exception ignored) {
            // best effort
        }
    }
}
