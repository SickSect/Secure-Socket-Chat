package org.ugina.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.ugina.crypto.AesCrypto;
import org.ugina.crypto.CryptoException;
import org.ugina.crypto.KeyLoader;
import org.ugina.crypto.RsaCrypto;
import org.ugina.protocol.ClientMessage;
import org.ugina.protocol.ServerMessage;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

public class ChatClient {
    private static final String HOST = "localhost";
    private static final int PORT = 5000;
    private static final SecretKey PSK_KEY;
    private static final ObjectMapper mapper = new ObjectMapper();
    private static final ConcurrentHashMap<String, PublicKey> keyCache = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, CompletableFuture<PublicKey>> pendingKeyRequests = new ConcurrentHashMap<>();

    static {
        try {
            PSK_KEY = KeyLoader.getSecretKey();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        // KEY GENERATION BEFORE START
        KeyPair pair = null;
        try {
            pair = RsaCrypto.generateKeyPair();
        } catch (CryptoException e) {
            throw new RuntimeException("[ERROR] RSA key generation failed", e);
        }
        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();
        // CONNECTION
        try (Socket socket = new Socket(HOST, PORT);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in))) {

            System.out.println("[client] connected to " + HOST + ":" + PORT);
            System.out.println("[client] type messages, /quit to exit");

            startReaderLoop(in, privateKey);
            startWriterLoop(stdin, out, publicKey);
        } catch (Exception e) {
            throw new RuntimeException("[ERROR] Main thread interrupted", e);
        }
    }

    /**
     * Writer thread that sending messages to server
     * @param stdin
     * @param out
     * @param publicKey
     */
    private static void startWriterLoop(BufferedReader stdin, PrintWriter out, PublicKey publicKey) {
        try{
            // GET NAME
            System.out.println("[client] Enter your name:");
            String clientName = stdin.readLine();
            out.println(ClientCipherService.encodeMessage(ClientMessage.join(clientName, publicKey)));

            while (true) {
                System.out.println("[client] Enter command: /msg or /quit");
                String cmd = stdin.readLine();
                if (cmd == null || "/quit".equals(cmd)) {
                    out.println(ClientCipherService.encodeMessage(ClientMessage.quit()));
                    break;
                }
                if ("/msg".equals(cmd)) {
                    System.out.println("[client] Enter receiver:");
                    String receiver = stdin.readLine();
                    System.out.println("[client] Enter message:");
                    String text = stdin.readLine();
                    SendMsgService.sendEncryptedMessage(text,receiver, clientName, out, keyCache, pendingKeyRequests);
                }
            }
        }catch (Exception ex){
            throw new RuntimeException("[ERROR] Writer thread interrupted", ex);
        }
    }

    /**
     * Reader thread that receiving messages from server
     * @param in
     * @param privateKey
     */
    private static void startReaderLoop(BufferedReader in, PrivateKey privateKey){
        Thread reader = new Thread(() -> {
            try {
                String line;
                while ((line = in.readLine()) != null) {
                    String decoded = AesCrypto.decrypt(line, PSK_KEY);
                    ServerMessage msg = mapper.readValue(decoded, ServerMessage.class);

                    switch (msg.type) {
                        case DM -> {
                            ReceiveMsgService.receiveDM(msg, privateKey);
                        }
                        case DELIVERED -> {
                            ReceiveMsgService.receivedDELIVERED(msg);
                        }
                        case ERROR -> System.out.println("[error: " + msg.errorCode + "] " + msg.text);
                        case SYSTEM -> System.out.println("[server] " + msg.text);
                        case PUBLIC_KEY -> {
                            PublicKey key = ReceiveMsgService.receivedPUBLIC_KEY(msg);
                            if (key != null) {
                                keyCache.put(msg.username, key);
                                CompletableFuture<PublicKey> futureKey = pendingKeyRequests.remove(msg.username);
                                if (futureKey != null) {
                                    futureKey.complete(key);
                                }
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
    }
}