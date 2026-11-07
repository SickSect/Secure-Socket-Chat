package org.ugina.Dto;

/**
 * Login / refresh response: a short-lived access JWT plus a long-lived,
 * single-use refresh token.
 */
public record LoginResponse(
        String token,
        long expiresAt,
        String refreshToken,
        long refreshExpiresAt
) {
}
