package org.ugina.crypto;

import javax.crypto.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RsaCrypto {
    private static final String TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        try{
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyPairGenerator.initialize(KEY_SIZE);
            return keyPairGenerator.generateKeyPair();
        }catch(NoSuchAlgorithmException e){
            throw new NoSuchAlgorithmException("Could not generate RSA key pair: " + e.getMessage());
        }
    }

    public static byte[] encrypt(byte[] plainText, PublicKey secretKey) throws CryptoException {
        try{
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(plainText);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException("[NoSuchPaddingException][RsaCrypto][encrypt] -" + e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("[NoSuchAlgorithmException][RsaCrypto][encrypt] -" + e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("[InvalidKeyException][RsaCrypto][encrypt] -" + e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException("[IllegalBlockSizeException][RsaCrypto][encrypt] -" + e);
        } catch (BadPaddingException e) {
            throw new RuntimeException("[BadPaddingException][RsaCrypto][encrypt] -" + e);
        }
    }

    public static byte[] decrypt(byte[] cipherText, PrivateKey secretKey) throws CryptoException {
        try{
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal(cipherText);
        } catch (NoSuchPaddingException e) {
            throw new CryptoException("[NoSuchPaddingException][RsaCrypto][encrypt]", e);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("[NoSuchAlgorithmException][RsaCrypto][encrypt] -",e);
        } catch (InvalidKeyException e) {
            throw new CryptoException("[InvalidKeyException][RsaCrypto][encrypt] -",e);
        } catch (IllegalBlockSizeException e) {
            throw new CryptoException("[IllegalBlockSizeException][RsaCrypto][encrypt] -",e);
        } catch (BadPaddingException e) {
            throw new CryptoException("[BadPaddingException][RsaCrypto][encrypt] -",e);
        }
    }

    public static String publicKeyToBase64(PublicKey key) {
        try{
            byte[] encoded = key.getEncoded();
            return Base64.getEncoder().encodeToString(encoded);
        } catch (Exception e) {
            throw new RuntimeException("[Exception][RsaCrypto][publicKeyToBase64] -",e);
        }
    }

    public static PublicKey publicKeyFromBase64(String base64) throws Exception {
        try{
            byte[] decoded = Base64.getDecoder().decode(base64);
            return KeyFactory.getInstance(ALGORITHM)
                    .generatePublic(new X509EncodedKeySpec(decoded));
        }catch (Exception e) {
            throw new RuntimeException("[Exception][RsaCrypto][publicKeyFromBase64] -" + e);
        }
    }

    public static String privateKeyToBase64(PrivateKey key) {
        try{
            byte[] encoded = key.getEncoded();
            return Base64.getEncoder().encodeToString(encoded);
        } catch (Exception e) {
            throw new RuntimeException("[Exception][RsaCrypto][publicKeyToBase64] -" + e);
        }
    }


    public static PrivateKey privateKeyFromBase64(String base64) throws Exception {
        try{
            byte[] decoded = Base64.getDecoder().decode(base64);
            return KeyFactory.getInstance(ALGORITHM)
                    .generatePrivate(new PKCS8EncodedKeySpec(decoded));
        }catch (Exception e) {
            throw new RuntimeException("[Exception][RsaCrypto][publicKeyFromBase64] -" + e);
        }
    }

}
