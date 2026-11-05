package org.ugina.client;

public class ChatClient {

    private static final String DEFAULT_HOST = "localhost";
    private static final int DEFAULT_CHAT_PORT = 5000;
    private static final String DEFAULT_AUTH_URL = "https://localhost:8443";

    public static void main(String[] args) {
        try {
            String host = setting("CHAT_HOST", DEFAULT_HOST);
            int port = parsePort(setting("CHAT_TLS_PORT", String.valueOf(DEFAULT_CHAT_PORT)));
            String authUrl = setting("AUTH_URL", DEFAULT_AUTH_URL);

            ConsoleTui tui = new ConsoleTui(authUrl);
            ChatClientCore core = new ChatClientCore(tui, host, port);
            tui.setCore(core);
            tui.run();
        } catch (Exception e) {
            System.err.println("[client] fatal: " + e.getMessage());
            System.exit(1);
        }
    }

    private static String setting(String name, String defaultValue) {
        String value = System.getProperty(name);
        if (value == null || value.isBlank()) {
            value = System.getenv(name);
        }
        return value == null || value.isBlank() ? defaultValue : value;
    }

    private static int parsePort(String value) {
        try {
            int port = Integer.parseInt(value);
            if (port < 1 || port > 65535) {
                throw new NumberFormatException("out of range");
            }
            return port;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid CHAT_TLS_PORT: " + value, e);
        }
    }
}
