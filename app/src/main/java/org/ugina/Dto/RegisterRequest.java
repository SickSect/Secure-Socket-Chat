package org.ugina.Dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "Username must not be blank")
        @Size(min = 3, max = 32, message = "Username must be 3-32 characters")
        @Pattern(regexp = "^[a-zA-Z0-9_]+$",
                message = "Username can only contain letters, digits, and underscores")
        String username,

        @NotBlank(message = "Password must not be blank")
        @Size(min = 8, max = 128, message = "Password must be 8-128 characters")
        String password,

        @NotBlank(message = "Public key must not be blank")
        String publicKey
) {}
