package org.ugina;

import org.testng.annotations.Test;
import org.ugina.crypto.exception.CryptoException;
import org.ugina.crypto.PbeUtil;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

public class PbeUtilTest {

    @Test
    public void testEncryptDecryptRoundtrip() throws Exception {
        byte[] original = "secret data".getBytes(StandardCharsets.UTF_8);
        char[] password = "my-strong-password".toCharArray();

        byte[] encrypted = PbeUtil.encrypt(original, password);
        byte[] decrypted = PbeUtil.decrypt(encrypted, password);

        assertEquals(new String(decrypted, StandardCharsets.UTF_8), "secret data");
    }

    @Test(expectedExceptions = CryptoException.class)
    public void testWrongPasswordFails() throws Exception {
        byte[] original = "secret".getBytes();
        char[] correct = "right".toCharArray();
        char[] wrong = "wrong".toCharArray();

        byte[] encrypted = PbeUtil.encrypt(original, correct);
        PbeUtil.decrypt(encrypted, wrong);  // должен упасть
    }

    @Test
    public void testDifferentCiphersEachTime() throws Exception {
        byte[] data = "same".getBytes();
        char[] pwd = "pass".toCharArray();

        byte[] e1 = PbeUtil.encrypt(data, pwd);
        byte[] e2 = PbeUtil.encrypt(data, pwd);

        assertNotEquals(Base64.getEncoder().encodeToString(e1),
                Base64.getEncoder().encodeToString(e2));
        // Должны быть разные — разный salt и разный IV каждый раз
    }
}
