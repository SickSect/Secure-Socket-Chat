package org.ugina.auth;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.ugina.repository.RefreshTokenRepository;
import org.ugina.utils.CustomLogger;

import java.time.Instant;

@Component
public class RefreshTokenCleaner {
    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenCleaner(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Scheduled(fixedRate = 3_600_000)
    public void cleanExpired() {
        int removed = refreshTokenRepository.deleteExpired(Instant.now());
        if (removed > 0) {
            CustomLogger.logInfo("Removed " + removed + " expired refresh tokens",
                    RefreshTokenCleaner.class.getName());
        }
    }
}
