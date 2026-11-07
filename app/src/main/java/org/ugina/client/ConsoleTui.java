package org.ugina.client;

import org.ugina.crypto.KeyFingerprint;
import org.ugina.crypto.RsaCrypto;
import org.ugina.utils.UsernamePolicy;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;

public class ConsoleTui implements ChatEventListener {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm");

    private ChatClientCore core;
    private final AuthClient authClient;
    private final KeyManager keyManager = new KeyManager();
    /** Set after a successful login; needed by /rotate-key (re-auth + local key). */
    private String loggedInUsername;

    public ConsoleTui(String serverBaseUrl) throws Exception {
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
                if (!handleRegister(stdin)) {
                    System.out.println("Registration did not complete; nothing was saved.");
                    return;
                }
                System.out.println("Now login with your credentials.");
            }

            LoginResult login = handleLogin(stdin);
            if (login == null) {
                return;
            }
            this.loggedInUsername = login.username();

            // Use the auto-refreshing accessor: the login token may already
            // be close to expiry if the user sat at the prompt.
            String accessToken = authClient.getValidAccessToken();
            boolean joined = core.connect(
                    login.username(),
                    accessToken != null ? accessToken : login.jwt(),
                    login.keyPair());
            if (!joined) {
                System.out.println("Could not join chat — token rejected or server unreachable");
                return;
            }
            runChatLoop(stdin);

        } finally {
            core.disconnect();
        }
    }

    private boolean handleRegister(BufferedReader stdin) throws Exception {
        System.out.print("Choose username: ");
        String username = stdin.readLine();
        if (username == null || username.isBlank()) {
            System.out.println("Username required");
            return false;
        }

        char[] passwordChars = readPassword(stdin, "Choose password: ");
        try {
            if (passwordChars.length == 0) {
                System.out.println("Password required");
                return false;
            }

            KeyPair keyPair = keyManager.createAndStore(username, passwordChars);
            String publicKeyBase64 = RsaCrypto.publicKeyToBase64(keyPair.getPublic());

            String error = authClient.register(
                    username, new String(passwordChars), publicKeyBase64);
            if (error == null) {
                System.out.println("Registered successfully!");
                return true;
            }

            // The server rejected the registration: do not leave an orphaned
            // private key on this device.
            keyManager.delete(username);
            System.out.println("Registration failed: " + error);
            return false;
        } catch (IllegalStateException e) {
            System.out.println(e.getMessage());
            return false;
        } finally {
            Arrays.fill(passwordChars, '\0');
        }
    }

    /**
     * Identity-key rotation (step-up): the password re-proves account
     * ownership, a fresh RSA pair replaces the local key file, and only the
     * public half goes to the server. If the server rejects the change, the
     * local file is rolled back — the device and the key directory must never
     * disagree.
     */
    private void handleRotateKey(BufferedReader stdin) throws Exception {
        if (loggedInUsername == null) {
            System.out.println("Not logged in");
            return;
        }
        System.out.println("This replaces your identity key.");
        System.out.println("Peers will see \"key changed\" and BLOCK messages until they");
        System.out.println("verify your new fingerprint and run: /trust "
                + loggedInUsername + " <prefix>");
        char[] passwordChars = readPassword(stdin, "Current password: ");
        try {
            if (passwordChars.length == 0) {
                System.out.println("Password required");
                return;
            }
            KeyPair oldKeyPair;
            try {
                // Loading the old key also verifies the password locally,
                // before anything is generated or written.
                oldKeyPair = keyManager.load(loggedInUsername, passwordChars);
            } catch (Exception e) {
                System.out.println("Wrong password or no local key: " + e.getMessage());
                return;
            }

            KeyPair newKeyPair = RsaCrypto.generateKeyPair();
            keyManager.store(loggedInUsername, newKeyPair, passwordChars);

            String error = authClient.rotateKey(new String(passwordChars),
                    RsaCrypto.publicKeyToBase64(newKeyPair.getPublic()));
            if (error != null) {
                // Roll back: the server still has the old key, so this device
                // must keep it too — otherwise the two sides disagree.
                keyManager.store(loggedInUsername, oldKeyPair, passwordChars);
                System.out.println("Rotation failed, local key restored: " + error);
                return;
            }

            String fingerprint = KeyFingerprint.hex(newKeyPair.getPublic());
            System.out.println("Identity key rotated.");
            System.out.println("New fingerprint: " + KeyFingerprint.format(fingerprint));
            System.out.println("Peers must verify it and run: /trust "
                    + loggedInUsername + " " + KeyFingerprint.shortForm(fingerprint));
            System.out.println("Existing sessions keep working; new handshakes use the new key.");
        } finally {
            Arrays.fill(passwordChars, '\0');
        }
    }

    private LoginResult handleLogin(BufferedReader stdin) throws Exception {
        System.out.print("Username: ");
        String username = stdin.readLine();
        if (username == null || username.isBlank()) {
            System.out.println("Username required");
            return null;
        }

        char[] passwordChars = readPassword(stdin, "Password: ");
        try {
            if (passwordChars.length == 0) {
                System.out.println("Password required");
                return null;
            }

            String jwt = authClient.login(username, new String(passwordChars));
            if (jwt == null) {
                System.out.println("Login failed — invalid credentials");
                return null;
            }

            KeyPair keyPair = keyManager.load(username, passwordChars);
            System.out.println("Logged in successfully!");
            return new LoginResult(jwt, username, keyPair);
        } finally {
            Arrays.fill(passwordChars, '\0');
        }
    }

    /**
     * Prefers a real no-echo console. Falls back to a visible line only when
     * the process is not attached to a terminal (for example in an IDE).
     */
    private static char[] readPassword(BufferedReader stdin, String prompt) throws IOException {
        Console console = System.console();
        System.out.print(prompt);
        if (console != null) {
            char[] password = console.readPassword();
            return password == null ? new char[0] : password;
        }
        System.out.println();
        System.out.println("(warning: no interactive console; password will be visible)");
        String line = stdin.readLine();
        return line == null ? new char[0] : line.toCharArray();
    }

    private void runChatLoop(BufferedReader stdin) throws Exception {
        String input;
        while ((input = stdin.readLine()) != null) {
            if (input.isBlank()) continue;
            try {
                if (!handleInput(input, stdin)) break;
            } catch (Exception e) {
                System.err.println("[client] error: " + e.getMessage());
            }
        }
    }

    private boolean handleInput(String input, BufferedReader stdin) throws Exception {
        String trimmed = input.trim();
        if (trimmed.equals("/quit")) return false;

        if (trimmed.equals("/help")) {
            printWelcome();
            return true;
        }

        if (trimmed.equals("/logout")) {
            authClient.logout();
            System.out.println("Logged out: refresh session revoked, access token invalidated");
            return false;
        }

        if (trimmed.equals("/rotate-key")) {
            handleRotateKey(stdin);
            return true;
        }

        if (trimmed.equals("/fingerprint")) {
            System.out.println("Your identity key fingerprint:");
            System.out.println("  " + KeyFingerprint.format(core.ownFingerprint()));
            System.out.println("Ask the other side for their /fingerprint output if you"
                    + " want to compare individual keys.");
            return true;
        }

        if (trimmed.equals("/safety") || trimmed.startsWith("/safety ")) {
            String[] parts = trimmed.split("\\s+");
            if (parts.length != 2 || !UsernamePolicy.isValid(parts[1])) {
                System.out.println("usage: /safety <user>");
                return true;
            }
            String peer = parts[1];
            try {
                String number = core.safetyNumber(peer);
                System.out.println("Safety number with " + peer + ":");
                System.out.println("  " + number);
                System.out.println("Peer key fingerprint: "
                        + KeyFingerprint.format(core.peerFingerprint(peer)));
                System.out.println("Compare this number with " + peer
                        + " over a separate channel (in person, phone, signed message).");
            } catch (Exception e) {
                System.out.println("Cannot compute safety number: " + e.getMessage());
            }
            return true;
        }

        if (trimmed.startsWith("/trust ")) {
            String rest = trimmed.substring("/trust ".length()).trim();
            int space = rest.indexOf(' ');
            if (space <= 0) {
                System.out.println("usage: /trust <user> <fingerprint-prefix>");
                return true;
            }
            String peer = rest.substring(0, space);
            String prefix = rest.substring(space + 1).trim();
            if (!UsernamePolicy.isValid(peer) || prefix.isBlank()) {
                System.out.println("usage: /trust <user> <fingerprint-prefix>");
                return true;
            }
            try {
                String fingerprint = core.trustPendingPeerKey(peer, prefix);
                System.out.println("Trusted new identity key for " + peer + ":");
                System.out.println("  " + KeyFingerprint.format(fingerprint));
                System.out.println("You can retry the message or /safety " + peer + " now.");
            } catch (Exception e) {
                System.out.println("Trust failed: " + e.getMessage());
            }
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
        System.out.println("  Secure Chat v0.7");
        System.out.println("─────────────────────────────────────────");
        System.out.println("  @<user> <text>   send a message");
        System.out.println("  /fingerprint     show your identity key fingerprint");
        System.out.println("  /safety <user>   show the safety number to compare out of band");
        System.out.println("  /trust <user> <fp>  trust a changed peer key after verification");
        System.out.println("  /logout           revoke the session and disconnect");
        System.out.println("  /rotate-key       replace your identity key (re-enter password)");
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
        if (text != null && text.startsWith("Session established with ")) {
            String peer = text.substring("Session established with ".length()).trim();
            System.out.println("[" + now() + "] [server] " + text
                    + " — verify: /safety " + peer);
        } else {
            System.out.println("[" + now() + "] [server] " + text);
        }
    }

    @Override
    public void onConnectionLost() {
        System.out.println("[" + now() + "] connection lost");
    }

    @Override
    public void onDecryptionFailed(String from) {
        System.out.println("[" + now() + "] failed to decrypt message from " + from);
    }

    @Override
    public void onPeerKeyTrusted(String username, String fingerprint, boolean firstContact) {
        if (firstContact) {
            System.out.println("[" + now() + "] [trust] first contact with " + username
                    + "; identity key: " + KeyFingerprint.format(fingerprint));
            System.out.println("[" + now() + "] [trust] compare /safety " + username
                    + " with " + username + " over a separate channel");
        } else {
            System.out.println("[" + now() + "] [trust] new identity key for " + username
                    + " accepted: " + KeyFingerprint.format(fingerprint));
        }
    }

    @Override
    public void onPeerKeyChanged(String username,
                                 String expectedFingerprint,
                                 String actualFingerprint) {
        System.out.println("[" + now() + "] [trust] WARNING: identity key for "
                + username + " changed!");
        System.out.println("  expected: " + KeyFingerprint.format(expectedFingerprint));
        System.out.println("  offered:  " + KeyFingerprint.format(actualFingerprint));
        System.out.println("  If " + username + " confirmed this key out of band, run:");
        System.out.println("  /trust " + username + " "
                + KeyFingerprint.shortForm(actualFingerprint));
    }
}
