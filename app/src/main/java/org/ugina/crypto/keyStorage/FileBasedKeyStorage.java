package org.ugina.crypto.keyStorage;

import org.ugina.crypto.PbeUtil;
import org.ugina.crypto.exception.CryptoException;
import org.ugina.crypto.exception.KeyStorageException;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Set;

public class FileBasedKeyStorage implements KeyStorage {
    private static final String ALGORITHM = "RSA";
    private static final Set<PosixFilePermission> OWNER_ONLY =
            PosixFilePermissions.fromString("rw-------");

    private final Path filePath;

    public FileBasedKeyStorage(Path filePath) {
        this.filePath = filePath;
    }

    @Override
    public boolean exists() {
        return Files.exists(filePath);
    }

    @Override
    public void save(KeyPair keyPair, char[] password) {
        byte[] privateKey = keyPair.getPrivate().getEncoded();
        byte[] encryptedPrivateKey = null;
        Path temp = null;
        try {
            byte[] publicKey = keyPair.getPublic().getEncoded();
            encryptedPrivateKey = PbeUtil.encrypt(privateKey, password);
            byte[] filePayload = new byte[4 + publicKey.length + encryptedPrivateKey.length];
            writeIntAt(filePayload, 0, publicKey.length);
            System.arraycopy(publicKey, 0, filePayload, 4, publicKey.length);
            System.arraycopy(encryptedPrivateKey, 0, filePayload, 4 + publicKey.length,
                    encryptedPrivateKey.length);

            Path directory = filePath.toAbsolutePath().getParent();
            if (directory != null) {
                Files.createDirectories(directory);
            }

            temp = Files.createTempFile(directory, "key-", ".tmp");
            Files.write(temp, filePayload);
            restrictPermissions(temp);
            moveAtomically(temp, filePath);
            temp = null;
        } catch (CryptoException | IOException e) {
            throw new KeyStorageException("Failed to save key pair", e);
        } catch (Exception e) {
            throw new KeyStorageException("Failed to save key pair", e);
        } finally {
            Arrays.fill(privateKey, (byte) 0);
            if (encryptedPrivateKey != null) {
                Arrays.fill(encryptedPrivateKey, (byte) 0);
            }
            if (temp != null) {
                try {
                    Files.deleteIfExists(temp);
                } catch (IOException ignored) {
                    // best effort
                }
            }
        }
    }

    @Override
    public KeyPair load(char[] password) throws KeyStorageException {
        byte[] privateKeyBytes = null;
        try {
            byte[] payload = Files.readAllBytes(filePath);
            if (payload.length < 4)
                throw new KeyStorageException("Key file is corrupt or empty", null);
            int publicKeylength = readIntAt(payload, 0);
            if (publicKeylength <= 0 || publicKeylength > payload.length - 4)
                throw new KeyStorageException("Key file has invalid format", null);
            byte[] publicKeyBytes = new byte[publicKeylength];
            System.arraycopy(payload, 4, publicKeyBytes, 0, publicKeylength);
            int encryptedStart = 4 + publicKeylength;
            byte[] encryptedPrivateKey = new byte[payload.length - encryptedStart];
            System.arraycopy(payload, encryptedStart, encryptedPrivateKey, 0,
                    encryptedPrivateKey.length);
            privateKeyBytes = PbeUtil.decrypt(encryptedPrivateKey, password);

            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            PrivateKey privateKey = keyFactory.generatePrivate(
                    new PKCS8EncodedKeySpec(privateKeyBytes));
            return new KeyPair(publicKey, privateKey);
        } catch (CryptoException e) {
            throw new KeyStorageException("Wrong password or corrupt key file", e);
        } catch (Exception e) {
            throw new KeyStorageException("Failed to load key pair", e);
        } finally {
            if (privateKeyBytes != null) {
                Arrays.fill(privateKeyBytes, (byte) 0);
            }
        }
    }

    private static void moveAtomically(Path source, Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void restrictPermissions(Path path) {
        try {
            Files.setPosixFilePermissions(path, OWNER_ONLY);
        } catch (UnsupportedOperationException | IOException ignored) {
            // Windows and some filesystems do not expose POSIX permissions.
        }
    }

    // --- Helpers for big-endian int encoding ---

    private static void writeIntAt(byte[] arr, int offset, int value) {
        arr[offset] = (byte) (value >>> 24);
        arr[offset + 1] = (byte) (value >>> 16);
        arr[offset + 2] = (byte) (value >>> 8);
        arr[offset + 3] = (byte) value;
    }

    private static int readIntAt(byte[] arr, int offset) {
        return ((arr[offset] & 0xFF) << 24)
                | ((arr[offset + 1] & 0xFF) << 16)
                | ((arr[offset + 2] & 0xFF) << 8)
                | (arr[offset + 3] & 0xFF);
    }
}
