package org.ugina.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.ugina.crypto.exception.CryptoException;
import org.ugina.crypto.HybridCrypto;
import org.ugina.protocol.ClientMessage;

import java.io.PrintWriter;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class SendMsgService {
    public static void sendEncryptedMessage(String text,
                                            String recipient,
                                            String sender,
                                            PrintWriter out,
                                            Map<String, PublicKey> keyCache,
                                            Map<String, CompletableFuture<PublicKey>> pendingKeyRequest) throws JsonProcessingException, ExecutionException, InterruptedException, TimeoutException, CryptoException {
        // GET KEY
        PublicKey theirKey = keyCache.get(recipient);
        if(theirKey == null){
            CompletableFuture<PublicKey> future = new CompletableFuture<>();
            pendingKeyRequest.put(recipient, future);
            out.println(ClientCipherService.encodeMessage(ClientMessage.getKey(recipient)));

            try{
                theirKey = future.get(5, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                pendingKeyRequest.remove(recipient);
                System.out.println("[client] unable to find recipient: " + recipient);
                return ;
            }
        }

        String e2ePayload = HybridCrypto.encrypt(text, theirKey);
        byte[] nonceBytes = new byte[16];
        new SecureRandom().nextBytes(nonceBytes);
        String nonce = Base64.getEncoder().encodeToString(nonceBytes);
        out.println(ClientCipherService.encodeMessage(ClientMessage.message(recipient, nonce, e2ePayload)));
    }
}
