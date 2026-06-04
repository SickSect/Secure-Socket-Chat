package org.ugina.crypto;

import org.ugina.crypto.exception.CryptoException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

public class HybridCrypto {
    private static final int RSA_ENCRYPTED_KEY_LENGTH = 256;
    private static final String ALGORITHM = "AES";

    // Зашифровать сообщение для конкретного получателя
    public static String encrypt(String plainText, PublicKey recipientPublicKey)
            throws CryptoException {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            keyGenerator.init(256);
            SecretKey secretKey = keyGenerator.generateKey();

            byte[] msgEncodedPayload = AesCrypto.encryptToByte(plainText, secretKey);
            byte[] keyEncoded = RsaCrypto.encrypt(secretKey.getEncoded(), recipientPublicKey);
            if (keyEncoded.length != RSA_ENCRYPTED_KEY_LENGTH) {
                throw new CryptoException("Unexpected RSA key length: " + keyEncoded.length, null);
            }
            byte[] payload = new byte[msgEncodedPayload.length + keyEncoded.length];
            System.arraycopy(keyEncoded, 0, payload, 0, RSA_ENCRYPTED_KEY_LENGTH);
            System.arraycopy(msgEncodedPayload,0, payload, RSA_ENCRYPTED_KEY_LENGTH, msgEncodedPayload.length);
            return Base64.getEncoder().encodeToString(payload);

        } catch (GeneralSecurityException e) {
            throw new CryptoException("[HybridCrypto][CryptoException][encryptFor]", e);
        }
    }

    // Расшифровать сообщение своим приватным ключом
    public static String decrypt(String base64Payload, PrivateKey ownPrivateKey)
            throws CryptoException {
        byte[] payload = Base64.getDecoder().decode(base64Payload);
        if (payload.length < RSA_ENCRYPTED_KEY_LENGTH) {
            throw new CryptoException(
                    "Payload too short: " + payload.length + " bytes, expected at least "
                            + RSA_ENCRYPTED_KEY_LENGTH, null);
        }
        byte[] keyEncodedPart = Arrays.copyOfRange(payload, 0, RSA_ENCRYPTED_KEY_LENGTH);
        byte[] msgEncodedPart = Arrays.copyOfRange(payload, RSA_ENCRYPTED_KEY_LENGTH, payload.length);

        byte[] decryptedKey = RsaCrypto.decrypt(keyEncodedPart, ownPrivateKey);
        SecretKey secretKey = new SecretKeySpec(decryptedKey, ALGORITHM);
        return AesCrypto.decryptFromBytes(msgEncodedPart, secretKey);
    }
}
