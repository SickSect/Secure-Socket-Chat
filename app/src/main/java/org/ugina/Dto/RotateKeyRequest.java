package org.ugina.Dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Step-up request: the access token identifies the session, the password
 * re-proves account ownership before the identity key may be replaced.
 */
public record RotateKeyRequest(
        @NotBlank String password,
        @NotBlank String publicKey
) {
}
