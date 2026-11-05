package org.ugina.config;

public record ChatTlsConfig(
        String keyStore,
        char[] keyStorePassword,
        char[] keyPassword
) {
}
