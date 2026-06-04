package org.ugina.crypto.keyStorage;

import com.fasterxml.jackson.core.util.RequestPayload;
import org.ugina.crypto.PbeUtil;
import org.ugina.crypto.exception.CryptoException;
import org.ugina.crypto.exception.KeyStorageException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class FileBasedKeyStorage implements KeyStorage{
    private static final String ALGORITHM = "RSA";
    private final Path filePath;

    public FileBasedKeyStorage(Path filePath) {
        this.filePath = filePath;
    }

    @Override
    public boolean exists() {
        return Files.exists(filePath);
    }

    @Override
    public void save(KeyPair keyPair, char[] password){
        try{
            // SERIALIZE
            byte[] publicKey = keyPair.getPublic().getEncoded();
            byte[] privateKey = keyPair.getPrivate().getEncoded();
            // CIPHER PRIVATE KEY
            byte[] encryptedPrivateKey = PbeUtil.encrypt(privateKey, password);
            byte[] filePayload = new byte[4 + publicKey.length + encryptedPrivateKey.length];
            writeIntAt(filePayload, 0, publicKey.length);
            System.arraycopy(publicKey, 0, filePayload, 4, publicKey.length);
            System.arraycopy(encryptedPrivateKey, 0, filePayload, 4 + publicKey.length, encryptedPrivateKey.length);
            if (filePath.getParent() != null)
                Files.createDirectories(filePath.getParent());
            Files.write(filePath, filePayload);

        } catch (CryptoException | IOException e) {
            throw new KeyStorageException("Failed to save key pair", e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public KeyPair load(char[] password) throws KeyStorageException {
        try{
            byte[] payload = Files.readAllBytes(filePath);
            if (payload.length < 4)
                throw new KeyStorageException("Key file is corrupt or empty", null);
            int publicKeylength = readIntAt(payload, 0);
            if (publicKeylength <= 0 || publicKeylength > payload.length - 4)
                throw new KeyStorageException("Key file has invalid format", null);
            byte[] publicKeyBytes = new byte[publicKeylength];
            System.arraycopy(payload, 4, publicKeyBytes,0, publicKeylength);
            int encryptedStart = 4 + publicKeylength;
            byte[] encryptedPrivateKey = new byte[payload.length - encryptedStart];
            System.arraycopy(payload, encryptedStart,encryptedPrivateKey, 0, encryptedPrivateKey.length);
            byte[] privateKeyBytes = PbeUtil.decrypt(encryptedPrivateKey, password);

            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
            return new KeyPair(publicKey, privateKey);
        }catch (CryptoException e) {
            throw new KeyStorageException("Wrong password or corrupt key file", e);
        } catch (Exception e) {
            throw new KeyStorageException("Failed to load key pair", e);
        }
    }

    // --- Хелперы для записи/чтения int в массив байт ---

    /**
     * Записать int (4 байта) в массив big-endian.
     * Big-endian = старший байт первым. Это стандарт для сетевых форматов.
     */
    private static void writeIntAt(byte[] arr, int offset, int value) {
        arr[offset]     = (byte) (value >>> 24);
        arr[offset + 1] = (byte) (value >>> 16);
        arr[offset + 2] = (byte) (value >>> 8);
        arr[offset + 3] = (byte) value;
    }

    /**
     * Прочитать int из 4 байт массива (big-endian).
     */
    private static int readIntAt(byte[] arr, int offset) {
        return ((arr[offset] & 0xFF) << 24)
                | ((arr[offset + 1] & 0xFF) << 16)
                | ((arr[offset + 2] & 0xFF) << 8)
                | (arr[offset + 3] & 0xFF);
    }
}
