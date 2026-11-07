package org.ugina.crypto;

import org.ugina.crypto.exception.CryptoException;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class EcdhCrypto {

    private static final String ALGORITHM = "EC";
    private static final String CURVE_NAME = "secp256r1";  // = P-256
    private static final String KEY_AGREEMENT_ALGORITHM = "ECDH";
    private static final int RAW_POINT_LENGTH = 1 + 32 + 32; // 0x04 || X || Y
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
     * Encodes a P-256 public key as a raw uncompressed point
     * {@code 0x04 || X(32) || Y(32)} — 65 bytes. Used for the ratchet public
     * key carried in every v3 message header, where full X.509 encoding would
     * add unnecessary bytes.
     */
    public static byte[] publicKeyToRaw(PublicKey publicKey) throws CryptoException {
        validatePublicKey(publicKey);
        ECPublicKey ecKey = (ECPublicKey) publicKey;
        byte[] raw = new byte[RAW_POINT_LENGTH];
        raw[0] = 0x04;
        byte[] x = fixedLength(ecKey.getW().getAffineX(), 32);
        byte[] y = fixedLength(ecKey.getW().getAffineY(), 32);
        System.arraycopy(x, 0, raw, 1, 32);
        System.arraycopy(y, 0, raw, 33, 32);
        return raw;
    }

    /**
     * Parses a raw uncompressed point and — unlike plain point decoding —
     * explicitly proves that the point lies on secp256r1 before it is used
     * for key agreement. Invalid points must never reach {@code KeyAgreement}.
     */
    public static PublicKey publicKeyFromRaw(byte[] raw) throws CryptoException {
        if (raw == null || raw.length != RAW_POINT_LENGTH || raw[0] != 0x04) {
            throw new CryptoException("Invalid raw EC point encoding", null);
        }
        try {
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(raw, 1, 33));
            BigInteger y = new BigInteger(1, Arrays.copyOfRange(raw, 33, 65));

            ECFieldFp field = (ECFieldFp) P256_PARAMS.getCurve().getField();
            BigInteger prime = field.getP();
            if (x.compareTo(prime) >= 0 || y.compareTo(prime) >= 0) {
                throw new CryptoException("EC point coordinate is out of range", null);
            }

            // y^2 == x^3 + a*x + b (mod p)
            BigInteger left = y.multiply(y).mod(prime);
            BigInteger right = x.multiply(x).multiply(x)
                    .add(P256_PARAMS.getCurve().getA().multiply(x))
                    .add(P256_PARAMS.getCurve().getB())
                    .mod(prime);
            if (!left.equals(right)) {
                throw new CryptoException("EC point is not on the P-256 curve", null);
            }

            ECPoint point = new ECPoint(x, y);
            return KeyFactory.getInstance(ALGORITHM)
                    .generatePublic(new ECPublicKeySpec(point, P256_PARAMS));
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("[EcdhCrypto][publicKeyFromRaw] failed", e);
        }
    }

    private static byte[] fixedLength(BigInteger value, int length) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == length) {
            return bytes;
        }
        byte[] out = new byte[length];
        if (bytes.length > length) {
            // BigInteger.toByteArray() may prepend a 0x00 sign byte.
            System.arraycopy(bytes, bytes.length - length, out, 0, length);
        } else {
            System.arraycopy(bytes, 0, out, length - bytes.length, bytes.length);
        }
        return out;
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
