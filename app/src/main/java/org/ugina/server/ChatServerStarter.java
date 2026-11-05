package org.ugina.server;

import org.ugina.auth.AuthProvider;
import org.ugina.config.ChatTlsConfigFactory;
import org.ugina.config.ChatTlsProperties;
import org.ugina.utils.CustomLogger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class ChatServerStarter implements CommandLineRunner {

    private final int port;
    private final boolean enabled;
    private final AuthProvider authProvider;
    private final ChatTlsProperties tlsProperties;
    private final ChatTlsConfigFactory tlsConfigFactory;

    public ChatServerStarter(
            @Value("${chat.tcp-port}") int port,
            @Value("${chat.tcp-enabled:true}") boolean enabled,
            AuthProvider authProvider,
            ChatTlsProperties tlsProperties,
            ChatTlsConfigFactory tlsConfigFactory
    ) {
        this.port = port;
        this.enabled = enabled;
        this.authProvider = authProvider;
        this.tlsProperties = tlsProperties;
        this.tlsConfigFactory = tlsConfigFactory;
    }

    @Override
    public void run(String... args) {
        if (!enabled) {
            return;
        }

        Thread thread = new Thread(() -> {
            try {
                ChatServer server = new ChatServer(
                        port, authProvider, tlsConfigFactory.create(tlsProperties));
                server.start();
            } catch (Exception e) {
                CustomLogger.logInfo(
                        "Chat server failed to start: " + e.getMessage(),
                        ChatServerStarter.class.getName());
            }
        }, "chat-server");
        thread.setDaemon(true);
        thread.start();
    }
}
