package org.ugina.crypto;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Properties;

public class KeyLoader {

    private static final String CONFIG_FILE = "application.properties";
    private static final String KEY_FILE = "chat.aes.key";

    public static SecretKey getSecretKey() throws GeneralSecurityException {
        Properties prop = new Properties();
        try(InputStream input = KeyLoader.class.getClassLoader()
                .getResourceAsStream(CONFIG_FILE)) {
            if (input == null) {
                throw new IOException("Could not find " + CONFIG_FILE);
            }
            prop.load(input);
            String base64Key = prop.getProperty(KEY_FILE);
            if (base64Key == null || base64Key.isBlank()) {
                throw new IOException("Could not find " + KEY_FILE);
            }
            byte[] decodedKey = Base64.getDecoder().decode(base64Key);
            if (decodedKey.length != 32) {
                throw new IOException("Invalid AES-256 key length: " + decodedKey.length + " (expected 32)");
            }
            return new SecretKeySpec(decodedKey, "AES");
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
