package org.ugina.auth;

import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.ugina.auth.exceptions.InvalidTokenException;
import org.ugina.entity.RefreshToken;
import org.ugina.repository.RefreshTokenRepository;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class RefreshTokenServiceTest {

    private RefreshTokenRepository repository;
    private RefreshTokenService service;

    @BeforeMethod
    public void setUp() {
        repository = Mockito.mock(RefreshTokenRepository.class);
        service = new RefreshTokenService(repository);
    }

    /**
     * create() should generate a token, save it, and return a non-blank string.
     */
    @Test
    public void createGeneratesAndSavesToken() {
        Long userId = 42L;

        String token = service.create(userId);

        assertNotNull(token);
        assertFalse(token.isBlank());
        verify(repository, times(1)).save(any(RefreshToken.class));
    }

    /**
     * A valid, non-expired token should resolve to its user id.
     */
    @Test
    public void validateReturnsUserIdForValidToken() throws Exception {
        RefreshToken entity = new RefreshToken();
        entity.setToken("valid-token");
        entity.setUserId(7L);
        entity.setExpiresAt(Instant.now().plus(1, ChronoUnit.DAYS));   // ещё жив

        when(repository.findByToken("valid-token")).thenReturn(Optional.of(entity));

        Long userId = service.validateAndGetUserId("valid-token");

        assertEquals(userId, Long.valueOf(7L));
    }

    /**
     * An unknown token should raise InvalidTokenException.
     */
    @Test(expectedExceptions = InvalidTokenException.class)
    public void validateThrowsForUnknownToken() throws Exception {
        when(repository.findByToken(anyString())).thenReturn(Optional.empty());

        service.validateAndGetUserId("does-not-exist");
    }

    /**
     * An expired token should raise InvalidTokenException AND be deleted.
     */
    @Test(expectedExceptions = InvalidTokenException.class)
    public void validateThrowsAndDeletesForExpiredToken() throws Exception {
        RefreshToken entity = new RefreshToken();
        entity.setToken("expired-token");
        entity.setUserId(9L);
        entity.setExpiresAt(Instant.now().minus(1, ChronoUnit.DAYS));   // истёк вчера

        when(repository.findByToken("expired-token")).thenReturn(Optional.of(entity));

        try {
            service.validateAndGetUserId("expired-token");
        } finally {
            // истёкший токен должен быть удалён
            verify(repository, times(1)).delete(any(RefreshToken.class));
        }
    }
}