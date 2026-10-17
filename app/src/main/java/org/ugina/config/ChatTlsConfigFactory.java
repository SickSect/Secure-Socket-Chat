package org.ugina.config;

import org.springframework.stereotype.Component;

@Component
public class ChatTlsConfigFactory {

    public ChatTlsConfig create(ChatTlsProperties properties) {
        return new ChatTlsConfig(
                properties.keyStore(),
                properties.keyStorePassword() != null
                        ? properties.keyStorePassword().toCharArray()
                        : new char[0],
                properties.keyPassword().toCharArray() != null
                        ? properties.keyPassword().toCharArray()
                        : properties.keyStorePassword() != null
                        ? properties.keyStorePassword().toCharArray()
                        : new char[0]
        );
    }
}