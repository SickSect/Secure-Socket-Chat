package org.ugina.crypto;

import org.ugina.crypto.exception.CryptoException;

import javax.crypto.KeyAgreement;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class EcdhCrypto {

    private static final String ALGORITHM = "EC";
    private static final String CURVE_NAME = "secp256r1";  // = P-256
    private static final String KEY_AGREEMENT_ALGORITHM = "ECDH";
    private static final ECParameterSpec P256_PARAMS = loadP256Params();

    public static KeyPair generateKeyPair() throws CryptoException {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyPairGenerator.initialize(new ECGenParameterSpec(CURVE_NAME));
            return keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new CryptoException("[EcdhCrypto][generateKeyPair] failed", e);
        }
    }

    public static byte[] computeSharedSecret(PrivateKeyHolder ownPrivateKey, PublicKey peerPublicKey)
            throws CryptoException {
        validatePublicKey(peerPublicKey);
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM);
            keyAgreement.init(ownPrivateKey.key());
            keyAgreement.doPhase(peerPublicKey, true);
            // THIS IS RAW ECDH SECRET! NOT A FINAL KEY!
            // It must be passed through HKDF before use.
            return keyAgreement.generateSecret();
        } catch (Exception e) {
            throw new CryptoException("[EcdhCrypto][computeSharedSecret] failed", e);
        }
    }

    /**
     * Compatibility overload. Prefer {@link #computeSharedSecret(PrivateKeyHolder, PublicKey)}
     * which is harder to call with a peer key by mistake.
     */
    public static byte[] computeSharedSecret(java.security.PrivateKey ownPrivateKey, PublicKey peerPublicKey)
            throws CryptoException {
        return computeSharedSecret(new PrivateKeyHolder(ownPrivateKey), peerPublicKey);
    }

    public static PublicKey publicKeyFromBase64(String base64PublicKey) throws CryptoException {
        try {
            byte[] decodedPublicKey = Base64.getDecoder().decode(base64PublicKey);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            PublicKey key = keyFactory.generatePublic(new X509EncodedKeySpec(decodedPublicKey));
            validatePublicKey(key);
            return key;
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("[EcdhCrypto][publicKeyFromBase64] failed", e);
        }
    }

    public static String publicKeyToBase64(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    /**
     * Only P-256 ephemeral keys are accepted. This prevents a peer from
     * downgrading the key exchange to a weaker curve.
     */
    public static void validatePublicKey(PublicKey publicKey) throws CryptoException {
        if (!(publicKey instanceof ECPublicKey ecKey)) {
            throw new CryptoException("Peer key is not an EC public key", null);
        }
        if (!sameParams(ecKey.getParams(), P256_PARAMS)) {
            throw new CryptoException("Peer key is not on the P-256 curve", null);
        }
    }

    private static boolean sameParams(ECParameterSpec a, ECParameterSpec b) {
        if (a == null || b == null) return false;
        return a.getCurve().getField().getFieldSize() == b.getCurve().getField().getFieldSize()
                && a.getCurve().getA().equals(b.getCurve().getA())
                && a.getCurve().getB().equals(b.getCurve().getB())
                && a.getGenerator().equals(b.getGenerator())
                && a.getOrder().equals(b.getOrder())
                && a.getCofactor() == b.getCofactor();
    }

    private static ECParameterSpec loadP256Params() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
            generator.initialize(new ECGenParameterSpec(CURVE_NAME));
            return ((ECPublicKey) generator.generateKeyPair().getPublic()).getParams();
        } catch (Exception e) {
            throw new IllegalStateException("P-256 is not available in this JVM", e);
        }
    }

    /**
     * Tiny wrapper that makes the "own private key" argument explicit at call
     * sites, reducing the risk of accidentally passing a peer key.
     */
    public record PrivateKeyHolder(java.security.PrivateKey key) {
    }
}
