package org.ugina.config;

import org.springframework.stereotype.Component;

import java.net.URI;
import java.nio.file.Path;

@Component
public class ChatTlsConfigFactory {

    public ChatTlsConfig create(ChatTlsProperties properties) {
        if (properties == null) {
            throw new IllegalStateException("Missing chat.tls configuration");
        }
        String keyStore = normalizePath(properties.keyStore());
        if (keyStore.isBlank()) {
            throw new IllegalStateException(
                    "chat.tls.key-store is not configured (set TLS_KEYSTORE)");
        }

        char[] storePassword = toChars(properties.keyStorePassword());
        if (storePassword.length == 0) {
            throw new IllegalStateException(
                    "chat.tls.key-store-password is not configured (set TLS_KEYSTORE_PASSWORD)");
        }
        char[] keyPassword = toChars(properties.keyPassword());
        if (keyPassword.length == 0) {
            keyPassword = storePassword.clone();
        }

        return new ChatTlsConfig(keyStore, storePassword, keyPassword);
    }

    /**
     * Spring binds {@code file:...} URLs as-is when the target type is String.
     * The TLS factories expect a plain filesystem path.
     */
    static String normalizePath(String raw) {
        if (raw == null) {
            return "";
        }
        String value = raw.trim();
        if (value.regionMatches(true, 0, "file:", 0, 5)) {
            try {
                return Path.of(URI.create(value)).toString();
            } catch (Exception ignored) {
                return value.substring(5);
            }
        }
        return value;
    }

    private static char[] toChars(String value) {
        return value == null ? new char[0] : value.toCharArray();
    }
}
