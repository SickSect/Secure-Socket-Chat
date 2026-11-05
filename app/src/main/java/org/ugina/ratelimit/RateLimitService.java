package org.ugina.ratelimit;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import org.springframework.stereotype.Service;
import org.ugina.config.RateLimitProperties;

import java.time.Duration;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RateLimitService {

    /** Hard cap so a flood of unique IPs cannot grow the map without bound. */
    private static final int MAX_BUCKETS = 10_000;
    private static final long IDLE_EVICTION_MS = 60 * 60 * 1000L;

    private final RateLimitProperties properties;
    private final ConcurrentHashMap<String, Entry> buckets = new ConcurrentHashMap<>();

    public RateLimitService(RateLimitProperties properties) {
        this.properties = properties;
    }

    /**
     * Attempts to consume one token for the given key.
     *
     * @return true if the request is allowed, false if the limit is exhausted
     */
    public boolean tryConsume(String key, RateLimitProperties.Limit limit) {
        if (key == null) {
            key = "unknown";
        }
        if (buckets.size() >= MAX_BUCKETS) {
            evictIdle();
            if (buckets.size() >= MAX_BUCKETS) {
                // Extremely unlikely: all buckets are active. Drop the cache
                // rather than grow without bound; the rate limits reset, but
                // the process stays alive.
                buckets.clear();
            }
        }
        long now = System.currentTimeMillis();
        Entry entry = buckets.compute(key, (k, existing) -> {
            if (existing == null) {
                return new Entry(newBucket(limit), now);
            }
            existing.lastUsedAt = now;
            return existing;
        });
        return entry.bucket.tryConsume(1);
    }

    private void evictIdle() {
        long cutoff = System.currentTimeMillis() - IDLE_EVICTION_MS;
        Iterator<Map.Entry<String, Entry>> iterator = buckets.entrySet().iterator();
        while (iterator.hasNext()) {
            if (iterator.next().getValue().lastUsedAt < cutoff) {
                iterator.remove();
            }
        }
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

    private static final class Entry {
        private final Bucket bucket;
        private volatile long lastUsedAt;

        private Entry(Bucket bucket, long lastUsedAt) {
            this.bucket = bucket;
            this.lastUsedAt = lastUsedAt;
        }
    }
}
