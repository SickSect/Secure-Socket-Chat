package org.ugina.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.ugina.config.JwtProperties;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Service
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);

    private static final String ISSUER = "secure-chat";
    private static final int MIN_SECRET_BYTES = 32;
    private static final int DEFAULT_EXPIRATION_MINUTES = 60;
    /** The value that used to be committed to the repository. */
    private static final String KNOWN_INSECURE_SECRET =
            "change-me-in-production-this-must-be-at-least-256-bits-long";

    private final SecretKey signingKey;
    private final int expirationMinutes;

    public JwtService(JwtProperties properties) {
        this.signingKey = Keys.hmacShaKeyFor(resolveSecret(properties.getSecret()));
        int configured = properties.getExpirationMinutes();
        this.expirationMinutes = configured > 0 ? configured : DEFAULT_EXPIRATION_MINUTES;
    }

    /**
     * Generates a JWT for a user.
     */
    public String generate(String username) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("username must not be blank");
        }
        Instant now = Instant.now();
        Instant expiry = now.plus(expirationMinutes, ChronoUnit.MINUTES);

        return Jwts.builder()
                .issuer(ISSUER)
                .subject(username)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .signWith(signingKey)
                .compact();
    }

    /**
     * Validates a JWT and returns the username from the subject.
     *
     * @throws JwtException if the token is invalid, expired or from another issuer
     */
    public String validateAndGetUsername(String token) throws JwtException {
        if (token == null || token.isBlank()) {
            throw new JwtException("Empty token");
        }
        Claims claims = Jwts.parser()
                .verifyWith(signingKey)
                .requireIssuer(ISSUER)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        String subject = claims.getSubject();
        if (subject == null || subject.isBlank()) {
            throw new JwtException("Token has no subject");
        }
        return subject;
    }

    /**
     * @return token expiry as an absolute epoch-millisecond value
     */
    public long getExpirationMillis() {
        return Instant.now()
                .plus(expirationMinutes, ChronoUnit.MINUTES)
                .toEpochMilli();
    }

    /**
     * Refuse to start with a missing, short or publicly known secret. A random
     * per-process secret is a safe fallback: tokens simply stop working after a
     * restart, which is far better than shipping a forgeable signing key.
     */
    private static byte[] resolveSecret(String configured) {
        if (configured != null) {
            String trimmed = configured.trim();
            byte[] bytes = trimmed.getBytes(StandardCharsets.UTF_8);
            if (bytes.length >= MIN_SECRET_BYTES
                    && !trimmed.equals(KNOWN_INSECURE_SECRET)
                    && !trimmed.equals("change-me-strong-secret")) {
                return bytes;
            }
        }
        byte[] random = new byte[MIN_SECRET_BYTES];
        new SecureRandom().nextBytes(random);
        log.warn("JWT_SECRET is missing, too short or insecure. "
                + "Generated a random ephemeral secret; existing tokens will be "
                + "invalid after restart. Set JWT_SECRET to a random value of at "
                + "least 32 bytes for production.");
        return random;
    }
}
