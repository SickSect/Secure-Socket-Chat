package org.ugina.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.ugina.crypto.AesCrypto;
import org.ugina.crypto.CryptoException;
import org.ugina.crypto.KeyLoader;
import org.ugina.crypto.RsaCrypto;
import org.ugina.protocol.ClientMessage;
import org.ugina.protocol.CommandType;
import org.ugina.protocol.ServerMessage;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class EchoClient {
    private static final String HOST = "localhost";
    private static final int PORT = 5000;
    private static final SecretKey KEY;
    private static final ObjectMapper mapper = new ObjectMapper();
    private static ConcurrentHashMap<String, PublicKey> keyCache = new ConcurrentHashMap<>();
    static {
        try {
            KEY = KeyLoader.getSecretKey();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws IOException, CryptoException {
        // KEY GENERATION BEFORE START
        KeyPair pair = RsaCrypto.generateKeyPair();
        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();
        // CONNECTION
        try (Socket socket = new Socket(HOST, PORT);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in))) {

            System.out.println("[client] connected to " + HOST + ":" + PORT);
            System.out.println("[client] type messages, /quit to exit");

            Thread reader = new Thread(() -> {
                try {
                    String line;
                    while ((line = in.readLine()) != null) {
                        String decoded = AesCrypto.decrypt(line, KEY);
                        ServerMessage msg = mapper.readValue(decoded, ServerMessage.class);

                        switch (msg.type) {
                            case DM -> System.out.println("[" + msg.fromClientName + "]: " + msg.text);
                            case DELIVERED -> System.out.println("[delivered]");
                            case ERROR -> System.out.println("[error: " + msg.errorCode + "] " + msg.text);
                            case SYSTEM -> System.out.println("[server] " + msg.text);
                            case PUBLIC_KEY -> {
                                try{
                                    PublicKey recievedKey = RsaCrypto.publicKeyFromBase64(msg.publicKey);
                                    keyCache.put(msg.username, recievedKey);
                                    System.out.println("[client] got public key for " + msg.username);
                                } catch (Exception e) {
                                    System.err.println("[client] failed to parse public key: " + e.getMessage());
                                }
                            }
                        }
                    }
                } catch (IOException e) {
                    System.out.println("[client]: connection lost");
                } catch (CryptoException e) {
                    System.out.println("[client]: decryption failed - " + e.getMessage());
                }
            });
            reader.setDaemon(true);
            reader.start();

            // GET NAME
            System.out.println("[client] Enter your name:");
            String clientName = stdin.readLine();
            ClientMessage joinMessage = new ClientMessage();
            joinMessage.commandType = CommandType.JOIN;
            joinMessage.username = clientName;
            joinMessage.publicKey = RsaCrypto.publicKeyToBase64(publicKey);
            out.println(ClientCipherService.encodeMessage(joinMessage));

            while (true) {
                System.out.println("[client] Enter command: /msg or /quit");
                String cmd = stdin.readLine();
                if (cmd == null || "/quit".equals(cmd)) {
                    ClientMessage quitMsg = new ClientMessage();
                    quitMsg.commandType = CommandType.QUIT;
                    out.println(ClientCipherService.encodeMessage(quitMsg));
                    break;
                }
                if ("/msg".equals(cmd)) {
                    System.out.println("[client] Enter receiver:");
                    String receiver = stdin.readLine();
                    System.out.println("[client] Enter message:");
                    String text = stdin.readLine();
                    ClientMessage msg = new ClientMessage();
                    msg.toClientName = receiver;
                    //msg.message = text;
                    msg.commandType = CommandType.SEND_MESSAGE;
                    out.println(ClientCipherService.encodeMessage(msg));
                }
            }
        }
    }
}