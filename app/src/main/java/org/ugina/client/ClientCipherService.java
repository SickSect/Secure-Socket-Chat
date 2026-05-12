package org.ugina.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.ugina.crypto.Crypto;
import org.ugina.crypto.CryptoException;
import org.ugina.crypto.KeyLoader;
import org.ugina.protocol.ClientMessage;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;

public class ClientCipherService {
    private static final ObjectMapper mapper = new ObjectMapper();
    private static SecretKey key = null;

    public static String encodeMessage(ClientMessage msg) throws JsonProcessingException {
        try{
            // TODO DELETE SOUT
            String json = mapper.writeValueAsString(msg);
            System.out.println("[ClientCipherService] encode msg: " + json);
            if (key == null)
                key = KeyLoader.getSecretKey();
            return Crypto.encrypt(json, key);

        }catch (JsonProcessingException e){
            throw new RuntimeException("[ClientCipherService - JsonProcessingException] Failed to encode message", e);
        } catch (CryptoException e) {
            throw new RuntimeException("[ClientCipherService - CryptoException] Failed to encode message", e);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("[ClientCipherService - GeneralSecurityException] Failed to encode message", e);
        }
    }
}
