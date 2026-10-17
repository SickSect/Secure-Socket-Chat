package org.ugina.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.nio.file.Path;

@ConfigurationProperties(prefix = "chat.tls")
public record ChatTlsProperties(
        Path keyStore,
        String keyStorePassword,
        String keyPassword
) {
}
