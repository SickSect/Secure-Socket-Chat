package org.ugina.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "rate-limit")
public class RateLimitProperties {

    private Limit register = new Limit();
    private Limit login = new Limit();

    @Getter
    @Setter
    public static class Limit {
        private int capacity;
        private int periodMinutes;
    }
}