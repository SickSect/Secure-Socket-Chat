package org.ugina.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.ugina.entity.RefreshToken;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String refreshToken);
    void deleteByToken(String refreshToken);
    void deleteByUserId(Long userId);
}
