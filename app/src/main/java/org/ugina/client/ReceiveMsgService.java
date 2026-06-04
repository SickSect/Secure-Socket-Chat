package org.ugina.client;

import org.ugina.crypto.exception.CryptoException;
import org.ugina.crypto.HybridCrypto;
import org.ugina.crypto.RsaCrypto;
import org.ugina.protocol.ServerMessage;

import java.security.PrivateKey;
import java.security.PublicKey;

public class ReceiveMsgService {
    public static void receiveDM(ServerMessage receivedMsg, PrivateKey clientPrivateKey) throws CryptoException {
        try{
            String plainText = HybridCrypto.decrypt(receivedMsg.e2ePayload, clientPrivateKey);
            System.out.println("[" + receivedMsg.fromClientName + "]: " + plainText);
        }catch (CryptoException e) {
            System.out.println("[" + receivedMsg.fromClientName + "] failed to decrypt message: " + e.getMessage());
        }
    }

    public static void receivedDELIVERED(ServerMessage receivedMsg) throws CryptoException {
        try{
            System.out.println("[ SERVER ] message to: " + receivedMsg.username + " DELIVERED");
        }catch (Exception e) {
            System.err.println("[ SERVER ] error while reading response from server: " + e.getMessage());
        }
    }

    public static PublicKey receivedPUBLIC_KEY(ServerMessage serverMsg){
        try {
            PublicKey publicKey = RsaCrypto.publicKeyFromBase64(serverMsg.publicKey);
            System.out.println("[CLIENT] Received public key for :" + serverMsg.username);
            return publicKey;
        } catch (Exception e) {
            System.err.println("[ SERVER ] error while decrypting public key from server : " + e.getMessage());
        }
        return null;
    }

    public static void receivedERROR(ServerMessage receivedMsg) throws CryptoException {

    }
}
