package org.ugina.client;

import org.ugina.crypto.keyStorage.FileBasedKeyStorage;
import org.ugina.crypto.keyStorage.KeyStorage;

import java.nio.file.Path;

public class ChatClient {

    private static final String HOST = "localhost";
    private static final int PORT = 5000;

    public static void main(String[] args) {
        try {
            ConsoleTui tui = new ConsoleTui();
            ChatClientCore core = new ChatClientCore(tui, HOST, PORT);
            tui.setCore(core);
            tui.run();
        } catch (Exception e) {
            System.err.println("[client] fatal: " + e.getMessage());
            System.exit(1);
        }
    }
}