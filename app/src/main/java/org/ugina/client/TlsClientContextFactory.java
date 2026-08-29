package org.ugina.client;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;

public class TlsClientContextFactory {

    public static SSLContext createSSLContext(Path truststorePath, char[] password) throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try(InputStream in = Files.newInputStream(truststorePath)) {
            trustStore.load(in, password);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(
                null,
                tmf.getTrustManagers(),
                new SecureRandom()
        );
        return sslContext;
    }
}
