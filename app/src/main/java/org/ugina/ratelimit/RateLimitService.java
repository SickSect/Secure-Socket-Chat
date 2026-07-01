package org.ugina.ratelimit;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import org.springframework.stereotype.Service;
import org.ugina.config.RateLimitProperties;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RateLimitService {

    private final RateLimitProperties properties;

    // ведро на каждый ключ (например "login:1.2.3.4")
    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    public RateLimitService(RateLimitProperties properties) {
        this.properties = properties;
    }

    /**
     * Attempts to consume one token for the given key.
     * @return true if the request is allowed, false if the limit is exhausted
     */
    public boolean tryConsume(String key, RateLimitProperties.Limit limit) {
        Bucket bucket = buckets.computeIfAbsent(key, k -> newBucket(limit));
        return bucket.tryConsume(1);
    }

    private Bucket newBucket(RateLimitProperties.Limit limit) {
        Bandwidth bandwidth = Bandwidth.builder()
                .capacity(limit.getCapacity())
                .refillIntervally(limit.getCapacity(), Duration.ofMinutes(limit.getPeriodMinutes()))
                .build();
        return Bucket.builder()
                .addLimit(bandwidth)
                .build();
    }

    public RateLimitProperties.Limit registerLimit() {
        return properties.getRegister();
    }

    public RateLimitProperties.Limit loginLimit() {
        return properties.getLogin();
    }
}