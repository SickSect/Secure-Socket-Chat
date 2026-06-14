package org.ugina.Dto;

public record LoginResponse(
        String token,
        long expiresAt
) {
}
