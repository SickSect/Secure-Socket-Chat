package org.ugina.crypto;

import org.ugina.crypto.exception.CryptoException;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class RsaSignature {
    private static final String ALGORITHM = "SHA256withRSA";

    public static byte[] sign(byte[] data, PrivateKey privateKey) throws CryptoException {
        Signature signature = null;
        try {
            signature = Signature.getInstance(ALGORITHM);
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            throw new CryptoException("[RsaSignature][sign] failed", e);
        }
    }

    public static boolean verify(byte[] data, byte[] signature, PublicKey publicKey) throws CryptoException {
        try{
            Signature verifier = Signature.getInstance(ALGORITHM);
            verifier.initVerify(publicKey);
            verifier.update(data);
            return verifier.verify(signature);
        } catch (Exception e) {
            throw new CryptoException("[RsaSignature][verify] failed", e);
        }
    }
}
