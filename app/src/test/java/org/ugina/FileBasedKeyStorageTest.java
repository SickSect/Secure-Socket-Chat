package org.ugina;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;
import org.ugina.crypto.RsaCrypto;
import org.ugina.crypto.exception.KeyStorageException;
import org.ugina.crypto.keyStorage.FileBasedKeyStorage;
import org.ugina.crypto.keyStorage.KeyStorage;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;

import static org.testng.Assert.*;

public class FileBasedKeyStorageTest {
    private final Path testFile = Path.of("target", "test-keys.dat");

    @AfterMethod
    public void cleanup() throws Exception {
        Files.deleteIfExists(testFile);
    }

    @Test
    public void testSaveAndLoad() throws Exception {
        KeyStorage storage = new FileBasedKeyStorage(testFile);
        KeyPair original = RsaCrypto.generateKeyPair();
        char[] password = "test-password-123".toCharArray();

        storage.save(original, password);
        assertTrue(storage.exists());

        KeyPair loaded = storage.load(password);
        assertEquals(loaded.getPublic(), original.getPublic());
        assertEquals(loaded.getPrivate(), original.getPrivate());
    }

    @Test
    public void testExistsReturnsFalseWhenNoFile() {
        KeyStorage storage = new FileBasedKeyStorage(testFile);
        assertFalse(storage.exists());
    }

    @Test(expectedExceptions = KeyStorageException.class)
    public void testWrongPasswordFails() throws Exception {
        KeyStorage storage = new FileBasedKeyStorage(testFile);
        KeyPair pair = RsaCrypto.generateKeyPair();

        storage.save(pair, "correct".toCharArray());
        storage.load("wrong".toCharArray());  // должно упасть
    }

    @Test
    public void testOverwriteWorks() throws Exception {
        KeyStorage storage = new FileBasedKeyStorage(testFile);
        char[] password = "pw".toCharArray();

        KeyPair first = RsaCrypto.generateKeyPair();
        storage.save(first, password);

        KeyPair second = RsaCrypto.generateKeyPair();
        storage.save(second, password);  // перезаписываем

        KeyPair loaded = storage.load(password);
        assertEquals(loaded.getPublic(), second.getPublic());
        assertNotEquals(loaded.getPublic(), first.getPublic());
    }
}
