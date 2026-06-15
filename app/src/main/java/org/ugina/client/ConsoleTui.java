package org.ugina.client;

import org.ugina.crypto.RsaCrypto;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

public class ConsoleTui implements ChatEventListener {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm");

    private ChatClientCore core;
    private final AuthClient authClient;
    private final KeyManager keyManager = new KeyManager();

    public ConsoleTui(String serverBaseUrl) {
        this.authClient = new AuthClient(serverBaseUrl);
    }

    public void setCore(ChatClientCore core) {
        this.core = core;
    }

    public void run() throws Exception {
        printWelcome();

        try (BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in))) {

            System.out.print("Choose: (1) register  (2) login: ");
            String choice = stdin.readLine();

            if ("1".equals(choice)) {
                handleRegister(stdin);
                // после регистрации просим залогиниться
                System.out.println("Now login with your credentials.");
            }

            // в обоих случаях дальше — логин
            String jwt = handleLogin(stdin);
            if (jwt == null) {
                return;  // логин не удался, сообщение уже выведено
            }

            // подключаемся к чату
            String loginName = lastLoginUsername;
            KeyPair keyPair = keyManager.load(loginName, lastLoginPassword);
            boolean joined = core.connect(jwt, keyPair);
            if (!joined) {
                System.out.println("Could not join chat — token rejected or server unreachable");
                return;
            }

            runChatLoop(stdin);

        } finally {
            core.disconnect();
        }
    }

    // временные поля чтобы пробросить креды от login к connect
    private String lastLoginUsername;
    private char[] lastLoginPassword;

    private void handleRegister(BufferedReader stdin) throws Exception {
        System.out.print("Choose username: ");
        String username = stdin.readLine();
        System.out.print("Choose password: ");
        String password = stdin.readLine();

        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            System.out.println("Username and password required");
            return;
        }

        try {
            // создаём и сохраняем ключи локально
            KeyPair keyPair = keyManager.createAndStore(username, password.toCharArray());
            String publicKeyBase64 = RsaCrypto.publicKeyToBase64(keyPair.getPublic());

            // регистрируем на сервере
            String error = authClient.register(username, password, publicKeyBase64);
            if (error == null) {
                System.out.println("Registered successfully!");
            } else {
                System.out.println("Registration failed: " + error);
            }
        } catch (IllegalStateException e) {
            System.out.println(e.getMessage());
        }
    }

    private String handleLogin(BufferedReader stdin) throws Exception {
        System.out.print("Username: ");
        String username = stdin.readLine();
        System.out.print("Password: ");
        String password = stdin.readLine();

        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            System.out.println("Username and password required");
            return null;
        }

        String jwt = authClient.login(username, password);
        if (jwt == null) {
            System.out.println("Login failed — invalid credentials");
            return null;
        }

        // сохраняем для последующей загрузки ключей
        lastLoginUsername = username;
        lastLoginPassword = password.toCharArray();

        System.out.println("Logged in successfully!");
        return jwt;
    }

    private void runChatLoop(BufferedReader stdin) throws Exception {
        String input;
        while ((input = stdin.readLine()) != null) {
            if (input.isBlank()) continue;
            try {
                if (!handleInput(input)) break;
            } catch (Exception e) {
                System.err.println("[client] error: " + e.getMessage());
            }
        }
    }

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
        System.out.println("  Secure Chat v0.5");
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

    // ─── ChatEventListener ───

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