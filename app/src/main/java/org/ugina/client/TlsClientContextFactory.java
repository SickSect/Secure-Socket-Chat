package org.ugina.client;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class TlsClientContextFactory {

    private static final String DEFAULT_TRUSTSTORE = "certs/client-truststore.p12";
    private static final String DEFAULT_TRUSTSTORE_PASSWORD = "changeit";

    public static SSLContext createSSLContext(Path truststorePath, char[] password)
            throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        if (truststorePath == null || !Files.isRegularFile(truststorePath)) {
            throw new IllegalStateException(
                    "TLS truststore not found: " + truststorePath
                            + ". Generate development certificates with "
                            + "certs/generate-dev-certs.ps1 (see certs/README.md).");
        }
        try {
            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(truststorePath)) {
                trustStore.load(in, password);
            }

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());
            return sslContext;
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to initialise TLS truststore " + truststorePath, e);
        }
    }

    public static SSLContext createDefaultContext() throws Exception {
        Path path = Path.of(setting("TLS_TRUSTSTORE", DEFAULT_TRUSTSTORE));
        char[] password = setting("TLS_TRUSTSTORE_PASSWORD", DEFAULT_TRUSTSTORE_PASSWORD)
                .toCharArray();
        return createSSLContext(path, password);
    }

    private static String setting(String name, String defaultValue) {
        String value = System.getProperty(name);
        if (value == null || value.isBlank()) {
            value = System.getenv(name);
        }
        return value == null || value.isBlank() ? defaultValue : value;
    }
}
