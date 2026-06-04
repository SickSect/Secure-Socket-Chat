package org.ugina.crypto;

import org.ugina.crypto.exception.CryptoException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HkdfCrypto {
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int HASH_LENGTH = 32;  // SHA-256 даёт 32 байта

    public static byte[] derive(byte[] ikm, byte[] salt, String info, int length) throws NoSuchAlgorithmException, CryptoException, InvalidKeyException {
        byte[] prk = extract(ikm, salt);
        return expand(prk, info.getBytes(StandardCharsets.UTF_8), length);
    }

    public static byte[] extract(byte[] ikm, byte[] salt) {
        try {
            if (salt == null || salt.length == 0)
                salt = new byte[HASH_LENGTH];
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(salt, HMAC_ALGORITHM));
            return mac.doFinal(ikm);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] expand(byte[] prk, byte[] info, int length) throws CryptoException, NoSuchAlgorithmException, InvalidKeyException {
        if (length > 255 * HASH_LENGTH)
            throw new CryptoException("Requested length " + length + " exceeds HKDF max", null);
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(prk, HMAC_ALGORITHM));
            byte[] output = new byte[length];
            byte[] prevBlock = new byte[0];
            int generated = 0;
            byte counter = 1;
            while (generated < length) {
                mac.reset();
                mac.update(prevBlock);
                mac.update(info);
                mac.update(counter);
                prevBlock = mac.doFinal();

                int toCopy = Math.min(HASH_LENGTH, length - generated);
                System.arraycopy(prevBlock, 0, output, generated, toCopy);
                generated += toCopy;
                counter++;
            }
            return output;
        } catch (Exception e) {
            throw new CryptoException("[Hkdf][expand] failed", e);
        }
    }
}
