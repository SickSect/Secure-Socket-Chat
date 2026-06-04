package org.ugina.client;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

/**
 * Консольный TUI. Реализует ChatEventListener для отображения событий
 * и читает ввод пользователя из stdin.
 */
public class ConsoleTui implements ChatEventListener {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm");

    private ChatClientCore core;

    public void setCore(ChatClientCore core) {
        this.core = core;
    }

    public void run() throws Exception {
        printWelcome();

        try (BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in))) {
            System.out.print("Your name: ");
            String name = stdin.readLine();
            if (name == null || name.isBlank()) {
                System.out.println("Empty name, exiting");
                return;
            }

            System.out.print("Password (for protecting your identity key): ");
            String passwordLine = stdin.readLine();
            if (passwordLine == null || passwordLine.isBlank()) {
                System.out.println("Empty password, exiting");
                return;
            }
            char[] password = passwordLine.toCharArray();

            boolean joined = core.connect(name, password);
            if (!joined){
                System.out.println("Could not connect — name may be taken or server unreachable");
                return;
            }

            String input;
            while ((input = stdin.readLine()) != null) {
                if (input.isBlank()) continue;
                try {
                    if (!handleInput(input)) break;
                } catch (Exception e) {
                    System.err.println("[client] error: " + e.getMessage());
                }
            }
        } finally {
            core.disconnect();
        }
    }

    /**
     * @return false если пользователь захотел выйти
     */
    private boolean handleInput(String input) throws Exception {
        if (input.equals("/quit")) return false;

        if (input.equals("/help")) {
            printWelcome();
            return true;
        }

        if (input.startsWith("@")) {
            int spaceIdx = input.indexOf(' ');
            if (spaceIdx == -1 || spaceIdx == input.length() - 1) {
                System.out.println("usage: @<user> <text>");
                return true;
            }
            String recipient = input.substring(1, spaceIdx);
            String text = input.substring(spaceIdx + 1);
            System.out.println("[" + now() + "] → " + recipient + ": " + text);
            core.sendMessage(recipient, text);
            return true;
        }

        System.out.println("unknown — type /help");
        return true;
    }

    private void printWelcome() {
        System.out.println();
        System.out.println("─────────────────────────────────────────");
        System.out.println("  Secure Chat v0.3");
        System.out.println("─────────────────────────────────────────");
        System.out.println("  @<user> <text>   send a message");
        System.out.println("  /help            show this help");
        System.out.println("  /quit            disconnect");
        System.out.println("─────────────────────────────────────────");
        System.out.println();
    }

    private static String now() {
        return LocalTime.now().format(TIME);
    }

    // ─── ChatEventListener ───────────────────────────────────

    @Override
    public void onMessage(String from, String text) {
        System.out.println("[" + now() + "] [" + from + "]: " + text);
    }

    @Override
    public void onDelivered() {
        System.out.println("[" + now() + "] ✓ delivered");
    }

    @Override
    public void onError(String code, String text) {
        System.out.println("[" + now() + "] ✗ " + code + ": " + text);
    }

    @Override
    public void onSystem(String text) {
        System.out.println("[" + now() + "] [server] " + text);
    }

    @Override
    public void onConnectionLost() {
        System.out.println("[" + now() + "] connection lost");
    }

    @Override
    public void onDecryptionFailed(String from) {
        System.out.println("[" + now() + "] failed to decrypt message from " + from);
    }
}