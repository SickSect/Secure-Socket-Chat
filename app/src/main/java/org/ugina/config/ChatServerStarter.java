package org.ugina.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.ugina.auth.AuthProvider;
import org.ugina.server.ChatServer;
import org.ugina.utils.CustomLogger;

@Component
@ConditionalOnProperty(name = "chat.tcp-enabled", havingValue = "true", matchIfMissing = true)
public class ChatServerStarter implements CommandLineRunner {
    private final ChatProperties chatProperties;
    private final AuthProvider authProvider;

    public ChatServerStarter(ChatProperties chatProperties, AuthProvider authProvider) {
        this.chatProperties = chatProperties;
        this.authProvider = authProvider;
    }

    @Override
    public void run(String... args) throws Exception {
        startTcpServer();
    }

    /**
     * Separated method for starting listening tcp server in thread
     */
    private void startTcpServer() {
        Thread thread = new Thread(() -> {
            try{
                ChatServer server = new ChatServer(chatProperties.getTcpPort(), authProvider);
                server.start();
            }catch(Exception e){
                CustomLogger.logInfo("Failed to start TCP server. Reason: %s".formatted(e.getMessage()), ChatServer.class.getName());
            }
        }, "chat-tcp-server");

        thread.setDaemon(false);
        thread.start();
    }
}
