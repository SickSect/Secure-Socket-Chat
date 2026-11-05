package org.ugina.crypto;

import org.ugina.crypto.exception.CryptoException;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RsaCrypto {
    private static final String TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;
    private static final int MIN_KEY_SIZE = 2048;
    private static final BigInteger MIN_PUBLIC_EXPONENT = BigInteger.valueOf(65537);

    public static KeyPair generateKeyPair() throws CryptoException {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyPairGenerator.initialize(KEY_SIZE);
            return keyPairGenerator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("[RsaCrypto][generateKeyPair] failed", e);
        }
    }

    public static byte[] encrypt(byte[] plainText, PublicKey publicKey) throws CryptoException {
        validatePublicKey(publicKey);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(plainText);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("[RsaCrypto][encrypt] failed", e);
        }
    }

    public static byte[] decrypt(byte[] cipherText, PrivateKey privateKey) throws CryptoException {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(cipherText);
        } catch (Exception e) {
            throw new CryptoException("[RsaCrypto][decrypt] failed", e);
        }
    }

    public static String publicKeyToBase64(PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static PublicKey publicKeyFromBase64(String base64) throws CryptoException {
        try {
            byte[] decoded = Base64.getDecoder().decode(base64);
            PublicKey key = KeyFactory.getInstance(ALGORITHM)
                    .generatePublic(new X509EncodedKeySpec(decoded));
            validatePublicKey(key);
            return key;
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("[RsaCrypto][publicKeyFromBase64] failed", e);
        }
    }

    public static String privateKeyToBase64(PrivateKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static PrivateKey privateKeyFromBase64(String base64) throws CryptoException {
        try {
            byte[] decoded = Base64.getDecoder().decode(base64);
            return KeyFactory.getInstance(ALGORITHM)
                    .generatePrivate(new PKCS8EncodedKeySpec(decoded));
        } catch (Exception e) {
            throw new CryptoException("[RsaCrypto][privateKeyFromBase64] failed", e);
        }
    }

    /**
     * Identity keys must be at least RSA-2048 with a sane public exponent.
     * Without this check a client could register a 512-bit key and weaken
     * the authentication of its own sessions.
     */
    public static void validatePublicKey(PublicKey publicKey) throws CryptoException {
        if (!(publicKey instanceof RSAPublicKey rsa)) {
            throw new CryptoException("Identity key is not an RSA public key", null);
        }
        if (rsa.getModulus().bitLength() < MIN_KEY_SIZE) {
            throw new CryptoException(
                    "RSA identity key is too small: " + rsa.getModulus().bitLength()
                            + " bits (minimum " + MIN_KEY_SIZE + ")", null);
        }
        if (rsa.getPublicExponent().compareTo(MIN_PUBLIC_EXPONENT) < 0) {
            throw new CryptoException("RSA public exponent is too small", null);
        }
    }
}
