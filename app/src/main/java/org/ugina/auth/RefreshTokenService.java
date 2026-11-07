package org.ugina.auth;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.ugina.auth.exceptions.InvalidTokenException;
import org.ugina.config.JwtProperties;
import org.ugina.entity.RefreshToken;
import org.ugina.entity.User;
import org.ugina.repository.RefreshTokenRepository;
import org.ugina.repository.UserRepository;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

/**
 * Issues, rotates and revokes refresh tokens.
 *
 * <p>The design follows the standard "short access + rotating refresh"
 * pattern:</p>
 *
 * <ul>
 *   <li><b>Hashed at rest</b> — only {@code HMAC-SHA256(JWT_SECRET, token)}
 *       is stored; the plaintext exists only in HTTP responses.</li>
 *   <li><b>Single use</b> — a presented token is marked {@code rotated_at}
 *       and a fresh token of the same <i>family</i> is issued.</li>
 *   <li><b>Reuse detection</b> — presenting an already-rotated or revoked
 *       token means it was stolen: the whole family is revoked and the user
 *       must log in again.</li>
 *   <li><b>Immediate access-token revocation</b> — logout bumps
 *       {@code users.token_version}, which invalidates every outstanding
 *       access JWT (including chat JOIN) on its next validation.</li>
 * </ul>
 *
 * <p>Synchronised per instance, consistent with the in-memory rate limiter:
 * this application is a single-node deployment.</p>
 */
@Service
public class RefreshTokenService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int REFRESH_TOKEN_BYTES = 32;

    private final RefreshTokenRepository repository;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final int refreshTokenDays;

    public RefreshTokenService(
            RefreshTokenRepository repository,
            UserRepository userRepository,
            JwtService jwtService,
            JwtProperties properties
    ) {
        this.repository = repository;
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.refreshTokenDays = properties.getRefreshTokenDays() > 0
                ? properties.getRefreshTokenDays()
                : 30;
    }

    /**
     * A fresh access/refresh pair for a successful login.
     */
    public record Issued(
            String accessToken,
            long accessExpiresAt,
            String refreshToken,
            long refreshExpiresAt
    ) {
    }

    /** Login: starts a new token family. */
    @Transactional
    public synchronized Issued issue(User user) {
        if (user == null || user.getId() == null) {
            throw new IllegalArgumentException("user must be persisted");
        }
        return issueInFamily(user, UUID.randomUUID().toString(), Instant.now());
    }

    /**
     * Exchanges a refresh token for a new pair (rotation).
     *
     * @throws InvalidTokenException for unknown, expired or already-used
     *         tokens; reuse additionally revokes the whole family
     */
    @Transactional
    public synchronized Issued rotate(String presented) throws InvalidTokenException {
        RefreshToken current = findByPlaintext(presented);
        Instant now = Instant.now();

        if (current.getRotatedAt() != null || current.getRevokedAt() != null) {
            // Replay of a spent token = the token leaked. Kill the session.
            revokeFamily(current.getFamilyId());
            throw new InvalidTokenException("Refresh token reuse detected; session revoked");
        }
        if (current.getExpiresAt().isBefore(now)) {
            current.setRevokedAt(now);
            repository.save(current);
            throw new InvalidTokenException("Refresh token expired");
        }

        User user = userRepository.findById(current.getUserId())
                .orElseThrow(() -> new InvalidTokenException("Token references unknown user"));

        current.setRotatedAt(now);
        repository.save(current);
        return issueInFamily(user, current.getFamilyId(), now);
    }

    /**
     * Logout: revokes the whole family and bumps {@code token_version}, so
     * every outstanding access JWT dies immediately. Idempotent — an unknown
     * token is silently ignored (no validity oracle for attackers).
     */
    @Transactional
    public synchronized void revoke(String presented) {
        if (presented == null || presented.isBlank()) {
            return;
        }
        Optional<RefreshToken> found =
                repository.findByTokenHash(jwtService.hashRefreshToken(presented));
        if (found.isEmpty()) {
            return;
        }
        RefreshToken current = found.get();
        revokeFamily(current.getFamilyId());
        userRepository.findById(current.getUserId()).ifPresent(user -> {
            user.setTokenVersion(user.getTokenVersion() + 1);
            userRepository.save(user);
        });
    }

    private Issued issueInFamily(User user, String familyId, Instant now) {
        String rawRefresh = newRefreshToken();
        RefreshToken stored = new RefreshToken();
        stored.setTokenHash(jwtService.hashRefreshToken(rawRefresh));
        stored.setFamilyId(familyId);
        stored.setUserId(user.getId());
        Instant refreshExpiresAt = now.plus(refreshTokenDays, ChronoUnit.DAYS);
        stored.setExpiresAt(refreshExpiresAt);
        repository.save(stored);

        String access = jwtService.generate(user.getUsername(), user.getTokenVersion());
        return new Issued(
                access,
                jwtService.getExpirationMillis(),
                rawRefresh,
                refreshExpiresAt.toEpochMilli());
    }

    private void revokeFamily(String familyId) {
        Instant now = Instant.now();
        for (RefreshToken token : repository.findByFamilyId(familyId)) {
            if (token.getRevokedAt() == null) {
                token.setRevokedAt(now);
                repository.save(token);
            }
        }
    }

    private RefreshToken findByPlaintext(String presented) throws InvalidTokenException {
        if (presented == null || presented.isBlank()) {
            throw new InvalidTokenException("Refresh token is required");
        }
        return repository.findByTokenHash(jwtService.hashRefreshToken(presented))
                .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));
    }

    private static String newRefreshToken() {
        byte[] raw = new byte[REFRESH_TOKEN_BYTES];
        RANDOM.nextBytes(raw);
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }
}
