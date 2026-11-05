package org.ugina.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "chat.tls")
public record ChatTlsProperties(
        String keyStore,
        String keyStorePassword,
        String keyPassword
) {
}
