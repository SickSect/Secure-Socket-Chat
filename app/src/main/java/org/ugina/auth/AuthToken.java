package org.ugina.auth;

/**
 * The result of a successful login: a short-lived access JWT and a
 * long-lived, single-use refresh token.
 */
public record AuthToken(
        String value,
        long expiresAt,
        String refreshToken,
        long refreshExpiresAt) {

}
