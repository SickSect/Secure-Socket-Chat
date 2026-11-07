package org.ugina.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 32)
    private String username;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(name = "public_key", nullable = false, columnDefinition = "TEXT")
    private String publicKey;

    /**
     * Backs the {@code ver} claim of access JWTs. Bumping this value
     * invalidates every outstanding access token for the user immediately
     * (logout, future password change / compromise response).
     */
    @Column(name = "token_version", nullable = false)
    private int tokenVersion = 1;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }
}
