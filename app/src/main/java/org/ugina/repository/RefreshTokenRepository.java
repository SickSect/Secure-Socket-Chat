package org.ugina.repository;

import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.ugina.entity.RefreshToken;

import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String refreshToken);
    void deleteByToken(String refreshToken);
    void deleteByUserId(Long userId);
    @Modifying
    @Transactional
    @Query("DELETE FROM RefreshToken t where t.expiresAt < :now")
    int deleteExpired(Instant now);
}
