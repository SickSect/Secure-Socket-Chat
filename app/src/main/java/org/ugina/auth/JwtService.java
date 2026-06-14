package org.ugina.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;
import org.ugina.config.JwtProperties;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Service
public class JwtService {

    private final SecretKey signingKey;
    private final int expirationMinutes;

    public JwtService(JwtProperties properties) {
        this.signingKey = Keys.hmacShaKeyFor(
                properties.getSecret().getBytes(StandardCharsets.UTF_8));
        this.expirationMinutes = properties.getExpirationMinutes();
    }

    /**
     * Генерирует JWT для пользователя.
     *
     * @param username имя пользователя (попадёт в subject)
     * @return подписанный JWT
     */
    public String generate(String username) {
        Instant now = Instant.now();
        Instant expiry = now.plus(expirationMinutes, ChronoUnit.MINUTES);

        return Jwts.builder()
                .subject(username)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .signWith(signingKey)
                .compact();
    }

    /**
     * Валидирует JWT и извлекает username.
     *
     * @param token JWT-строка
     * @return username из subject
     * @throws JwtException если токен невалиден или истёк
     */
    public String validateAndGetUsername(String token) throws JwtException {
        Claims claims = Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims.getSubject();
    }

    /**
     * @return время жизни токена в миллисекундах от текущего момента
     */
    public long getExpirationMillis() {
        return Instant.now()
                .plus(expirationMinutes, ChronoUnit.MINUTES)
                .toEpochMilli();
    }
}
