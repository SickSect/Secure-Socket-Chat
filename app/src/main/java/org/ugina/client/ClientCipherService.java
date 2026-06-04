package org.ugina.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.ugina.crypto.AesCrypto;
import org.ugina.crypto.KeyLoader;
import org.ugina.protocol.ClientMessage;

import javax.crypto.SecretKey;

public class ClientCipherService {
    private static final ObjectMapper mapper = new ObjectMapper();
    private static SecretKey psk = null;

    public static String encodeMessage(ClientMessage msg) throws JsonProcessingException {
        try {
            if (psk == null) psk = KeyLoader.getSecretKey();
            String json = mapper.writeValueAsString(msg);
            return AesCrypto.encrypt(json, psk);
        } catch (Exception e) {
            throw new RuntimeException("Failed to encode message", e);
        }
    }
}
