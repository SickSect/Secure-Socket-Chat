package org.ugina.crypto;

import java.security.SecureRandom;
import java.util.Base64;

public class KeyGenUtil {
    public static void main(String[] args) {
        byte[] key = new byte[32];  // 256 бит для AES-256
        new SecureRandom().nextBytes(key);
        String base64 = Base64.getEncoder().encodeToString(key);
        System.out.println("Generated AES-256 key (Base64):");
        System.out.println(base64);
        System.out.println();
        System.out.println("Put this into application.properties:");
        System.out.println("chat.aes.key=" + base64);
    }
}
