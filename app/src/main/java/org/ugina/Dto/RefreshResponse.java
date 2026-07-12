package org.ugina.Dto;

public record RefreshResponse(
        String token,
        long expiresAt
) {
}
