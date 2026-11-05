package org.ugina.server;

import org.ugina.config.ChatTlsConfig;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;

public final class TlsServerContextFactory {

    private TlsServerContextFactory() {
    }

    public static SSLContext createSSLContext(ChatTlsConfig config) throws Exception {
        if (config == null) {
            throw new IllegalStateException("TLS configuration is missing");
        }
        return createSSLContext(
                Path.of(config.keyStore()),
                config.keyStorePassword(),
                config.keyPassword());
    }

    /**
     * Compatibility overload: one password for both the store and the key.
     */
    public static SSLContext createSSLContext(Path keystorePath, char[] password) throws Exception {
        return createSSLContext(keystorePath, password, password);
    }

    public static SSLContext createSSLContext(
            Path keystorePath,
            char[] storePassword,
            char[] keyPassword
    ) throws Exception {
        if (keystorePath == null || !Files.isRegularFile(keystorePath)) {
            throw new IllegalStateException(
                    "TLS keystore not found: " + keystorePath
                            + ". Generate development certificates with "
                            + "certs/generate-dev-certs.ps1 (see certs/README.md) "
                            + "or set TLS_KEYSTORE to a valid PKCS#12 file.");
        }
        if (storePassword == null || storePassword.length == 0) {
            throw new IllegalStateException(
                    "TLS keystore password is not configured (set TLS_KEYSTORE_PASSWORD)");
        }

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystorePath)) {
            keyStore.load(in, storePassword);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Cannot open TLS keystore " + keystorePath
                            + " (wrong TLS_KEYSTORE_PASSWORD or corrupt file)", e);
        }

        char[] effectiveKeyPassword = (keyPassword == null || keyPassword.length == 0)
                ? storePassword
                : keyPassword;
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        try {
            kmf.init(keyStore, effectiveKeyPassword);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Cannot unlock the private key in " + keystorePath
                            + " (check TLS_KEY_PASSWORD)", e);
        }

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());
        return sslContext;
    }
}
