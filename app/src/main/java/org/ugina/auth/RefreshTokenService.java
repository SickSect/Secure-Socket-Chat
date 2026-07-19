package org.ugina.auth;

import org.springframework.stereotype.Service;
import org.ugina.auth.exceptions.InvalidTokenException;
import org.ugina.entity.RefreshToken;
import org.ugina.repository.RefreshTokenRepository;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    // refresh-токен живёт 7 дней
    private static final long VALIDITY_DAYS = 7;
    private final SecureRandom secureRandom = new SecureRandom();

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public String create(Long userId){
        if (userId == null)
            return null;
        String token = generateTokenString();

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUserId(userId);
        refreshToken.setToken(token);
        refreshToken.setExpiresAt(Instant.now().plus(VALIDITY_DAYS, ChronoUnit.DAYS));
        refreshTokenRepository.save(refreshToken);
        return token;
    }

    private String generateTokenString() {
        byte[] bytes = new byte[32];       // 256 бит случайности
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public Long validateAndGetUserId(String token) throws InvalidTokenException {
        RefreshToken entity = refreshTokenRepository.findByToken(token).orElseThrow( () ->
                new InvalidTokenException("Refresh token not found"));
        if (entity.getExpiresAt().isBefore(Instant.now())) {
            refreshTokenRepository.delete(entity);
            throw new InvalidTokenException("Refresh token expired");
        }
        return entity.getUserId();
    }
}
