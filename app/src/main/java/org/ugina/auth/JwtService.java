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
    /**
     * Access tokens are intentionally short-lived: they cannot be revoked
     * individually, so the damage window of a stolen token is bounded by
     * this TTL. Long-lived sessions use refresh tokens instead.
     */
    private static final int DEFAULT_EXPIRATION_MINUTES = 10;
    /** Claim carrying {@code users.token_version} — bumping it kills all access tokens. */
    public static final String CLAIM_TOKEN_VERSION = "ver";
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
     * A validated access token: who it belongs to and which
     * {@code users.token_version} it was minted under.
     */
    public record Validated(String username, int tokenVersion) {
    }

    /**
     * Generates a JWT for a user (token version 1 — for callers that do not
     * track versions, e.g. legacy paths and tests).
     */
    public String generate(String username) {
        return generate(username, 1);
    }

    /**
     * Generates a short-lived access JWT bound to the user's current token
     * version. The version claim lets the server invalidate every outstanding
     * token at once by bumping one integer.
     */
    public String generate(String username, int tokenVersion) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("username must not be blank");
        }
        Instant now = Instant.now();
        Instant expiry = now.plus(expirationMinutes, ChronoUnit.MINUTES);

        return Jwts.builder()
                .issuer(ISSUER)
                .subject(username)
                .id(java.util.UUID.randomUUID().toString())   // unique token id (jti)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .claim(CLAIM_TOKEN_VERSION, tokenVersion)
                .signWith(signingKey)
                .compact();
    }

    /**
     * Validates a JWT and returns its subject plus token version.
     *
     * @throws JwtException if the token is invalid, expired or from another issuer
     */
    public Validated validate(String token) throws JwtException {
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
        Integer version = claims.get(CLAIM_TOKEN_VERSION, Integer.class);
        // Tokens minted before v0.7 have no claim; treat them as version 1 so
        // a rolling upgrade does not log every user out mid-session.
        return new Validated(subject, version == null ? 1 : version);
    }

    /**
     * Validates a JWT and returns the username from the subject.
     *
     * @throws JwtException if the token is invalid, expired or from another issuer
     */
    public String validateAndGetUsername(String token) throws JwtException {
        return validate(token).username();
    }

    /**
     * Keyed hash (HMAC-SHA256 with the JWT secret) of a refresh token. Only
     * this value is stored: a database leak yields no usable refresh tokens,
     * and without {@code JWT_SECRET} an attacker cannot even verify a guess.
     */
    public String hashRefreshToken(String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("token must not be blank");
        }
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(signingKey);
            return java.util.HexFormat.of().formatHex(
                    mac.doFinal(token.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("Cannot hash refresh token", e);
        }
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
