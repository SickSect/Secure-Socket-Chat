package org.ugina.config;

import java.nio.file.Path;

public record ChatTlsConfig(
        Path keyStore,
        char[] keyStorePassword,
        char [] keyPassword
) {
}
