package org.ugina.client;

public class ChatClient {

    private static final String HOST = "localhost";
    private static final int PORT = 5000;
    private static final String AUTH_URL = "https://localhost:8443";

    public static void main(String[] args) {
        try {
            ConsoleTui tui = new ConsoleTui(AUTH_URL);
            ChatClientCore core = new ChatClientCore(tui, "localhost", 5000);
            tui.setCore(core);
            tui.run();
        } catch (Exception e) {
            System.err.println("[client] fatal: " + e.getMessage());
            System.exit(1);
        }
    }
}