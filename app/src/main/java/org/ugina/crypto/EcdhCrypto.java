package org.ugina.crypto;

import org.ugina.crypto.exception.CryptoException;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class EcdhCrypto {

    private static final String ALGORITHM = "EC";
    private static final String CURVE_NAME = "secp256r1";  // = P-256
    private static final String KEY_AGREEMENT_ALGORITHM = "ECDH";

    public static KeyPair generateKeyPair() throws CryptoException {
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyPairGenerator.initialize(new ECGenParameterSpec(CURVE_NAME));
            return keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new CryptoException("[EcdhCrypto][generateKeyPair] failed", e);
        }
    }

    public static byte[] computeSharedSecret(PrivateKey ownPrivateKey, PublicKey peerPublicKey) throws CryptoException {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM);
            keyAgreement.init(ownPrivateKey);
            keyAgreement.doPhase(peerPublicKey, true);
            // THIS IS RAW ECDH SECRET? NOT A FINAL KEY!
            return keyAgreement.generateSecret();
        } catch (Exception e) {
            throw new CryptoException("[EcdhCrypto][computeSharedSecret] failed", e);
        }
    }

    public static PublicKey publicKeyFromBase64(String base64PublicKey) throws CryptoException {
        try{
            byte[] decodedPublicKey = Base64.getDecoder().decode(base64PublicKey);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            return keyFactory.generatePublic(new X509EncodedKeySpec(decodedPublicKey));
        }catch (Exception e){
            throw new CryptoException("[EcdhCrypto][publicKeyFromBase64] failed", e);
        }
    }

    public static String publicKeyToBase64(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }
}
