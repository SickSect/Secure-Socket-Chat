package org.ugina.server;

import org.ugina.auth.AuthProvider;
import org.ugina.config.ChatTlsConfig;
import org.ugina.config.ChatTlsProperties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class ChatServerStarter implements CommandLineRunner {

    private final int port;
    private final boolean enabled;
    private final AuthProvider authProvider;
    private final ChatTlsProperties tlsProperties;

    public ChatServerStarter(
            @Value("${chat.tcp-port}") int port,
            @Value("${chat.tcp-enabled}") boolean enabled,
            AuthProvider authProvider,
            ChatTlsProperties tlsProperties
    ) {
        this.port = port;
        this.enabled = enabled;
        this.authProvider = authProvider;
        this.tlsProperties = tlsProperties;
    }

    @Override
    public void run(String... args) {
        if (!enabled) {
            return;
        }

        ChatTlsConfig tlsConfig = new ChatTlsConfig(
                tlsProperties.keyStore(),
                tlsProperties.keyStorePassword() != null
                        ? tlsProperties.keyStorePassword().toCharArray()
                        : new char[0],
                tlsProperties.keyPassword().toCharArray()
        );

        ChatServer server = new ChatServer(port, authProvider, tlsConfig);

        Thread thread = new Thread(() -> {
            try {
                server.start();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        thread.setDaemon(true);
        thread.start();
    }
}