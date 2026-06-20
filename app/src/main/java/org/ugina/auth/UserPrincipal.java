package org.ugina.auth;

public record UserPrincipal(
        String username,
        String publicKey
) {
}
