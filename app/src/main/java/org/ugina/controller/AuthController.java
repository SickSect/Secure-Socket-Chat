package org.ugina.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.ugina.Dto.LoginRequest;
import org.ugina.Dto.LoginResponse;
import org.ugina.Dto.LogoutRequest;
import org.ugina.Dto.RefreshRequest;
import org.ugina.Dto.RegisterRequest;
import org.ugina.Dto.RotateKeyRequest;
import org.ugina.auth.AuthProvider;
import org.ugina.auth.AuthToken;
import org.ugina.auth.RefreshTokenService;
import org.ugina.auth.UserPrincipal;
import org.ugina.auth.exceptions.AuthenticationException;
import org.ugina.auth.exceptions.InvalidTokenException;
import org.ugina.ratelimit.RateLimitExceededException;
import org.ugina.ratelimit.RateLimitService;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthProvider authProvider;
    private final RefreshTokenService refreshTokenService;
    private final RateLimitService rateLimitService;

    public AuthController(AuthProvider authProvider,
                          RefreshTokenService refreshTokenService,
                          RateLimitService rateLimitService) {
        this.authProvider = authProvider;
        this.refreshTokenService = refreshTokenService;
        this.rateLimitService = rateLimitService;
    }


    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@Valid @RequestBody RegisterRequest request,
                                                        HttpServletRequest httpRequest) {

        String ip = httpRequest.getRemoteAddr();
        if (!rateLimitService.tryConsume("register:" + ip, rateLimitService.registerLimit())) {
            throw new RateLimitExceededException("Too many registration attempts. Try again later.");
        }
        UserPrincipal principal = authProvider.register(
                request.username(),
                request.password(),
                request.publicKey()
        );

        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "status", "registered",
                "username", principal.username()
        ));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request,
                                               HttpServletRequest httpRequest) throws AuthenticationException {
        String ip = httpRequest.getRemoteAddr();
        if (!rateLimitService.tryConsume("login:" + ip, rateLimitService.loginLimit())) {
            throw new RateLimitExceededException("Too many login attempts. Try again later.");
        }
        AuthToken token = authProvider.authenticate(request.username(), request.password());
        return ResponseEntity.ok(new LoginResponse(
                token.value(), token.expiresAt(),
                token.refreshToken(), token.refreshExpiresAt()));
    }

    /**
     * Exchanges a single-use refresh token for a new access/refresh pair.
     * Replaying a spent token revokes the whole session (reuse detection).
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@Valid @RequestBody RefreshRequest request,
                                     HttpServletRequest httpRequest) {
        String ip = httpRequest.getRemoteAddr();
        if (!rateLimitService.tryConsume("refresh:" + ip, rateLimitService.refreshLimit())) {
            throw new RateLimitExceededException("Too many refresh attempts. Try again later.");
        }
        try {
            RefreshTokenService.Issued issued = refreshTokenService.rotate(request.refreshToken());
            return ResponseEntity.ok(new LoginResponse(
                    issued.accessToken(), issued.accessExpiresAt(),
                    issued.refreshToken(), issued.refreshExpiresAt()));
        } catch (InvalidTokenException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "error", "INVALID_TOKEN",
                    "message", e.getMessage()
            ));
        }
    }

    /**
     * Logout: revokes the token family and bumps the user's token version,
     * so every outstanding access JWT (chat JOIN included) dies immediately.
     * Idempotent — an unknown token still returns success.
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(@RequestBody LogoutRequest request,
                                                      HttpServletRequest httpRequest) {
        String ip = httpRequest.getRemoteAddr();
        if (!rateLimitService.tryConsume("refresh:" + ip, rateLimitService.refreshLimit())) {
            throw new RateLimitExceededException("Too many attempts. Try again later.");
        }
        refreshTokenService.revoke(request.refreshToken());
        return ResponseEntity.ok(Map.of("status", "logged_out"));
    }

    /**
     * Identity-key rotation (step-up): requires a live access token AND the
     * account password — a stolen access token alone cannot swap the key.
     * Shares the password-guessing budget with /login.
     */
    @PostMapping("/rotate-key")
    public ResponseEntity<?> rotateKey(@Valid @RequestBody RotateKeyRequest request,
                                       @RequestHeader(value = "Authorization",
                                               required = false) String authorization,
                                       HttpServletRequest httpRequest)
            throws AuthenticationException {
        String ip = httpRequest.getRemoteAddr();
        if (!rateLimitService.tryConsume("login:" + ip, rateLimitService.loginLimit())) {
            throw new RateLimitExceededException("Too many attempts. Try again later.");
        }

        String token = bearerToken(authorization);
        if (token == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "error", "INVALID_TOKEN",
                    "message", "Missing bearer access token"));
        }
        UserPrincipal caller;
        try {
            caller = authProvider.validate(token);
        } catch (InvalidTokenException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "error", "INVALID_TOKEN",
                    "message", e.getMessage()));
        }

        // Wrong password -> AuthenticationException ->401, bad key ->
        // RegistrationException ->409: both are mapped by GlobalExceptionHandler.
        UserPrincipal updated = authProvider.rotateKey(
                caller.username(), request.password(), request.publicKey());
        return ResponseEntity.ok(Map.of(
                "status", "key_rotated",
                "username", updated.username()
        ));
    }

    /** Extracts the token from an {@code Authorization: Bearer ...} header. */
    private static String bearerToken(String header) {
        if (header == null) {
            return null;
        }
        String value = header.trim();
        if (value.regionMatches(true, 0, "Bearer ", 0, 7)) {
            value = value.substring(7).trim();
        }
        return value.isEmpty() ? null : value;
    }
}
