package org.ugina;

import org.mockito.ArgumentCaptor;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.ugina.auth.JwtService;
import org.ugina.auth.RefreshTokenService;
import org.ugina.auth.exceptions.InvalidTokenException;
import org.ugina.config.JwtProperties;
import org.ugina.entity.RefreshToken;
import org.ugina.entity.User;
import org.ugina.repository.RefreshTokenRepository;
import org.ugina.repository.UserRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

/**
 * Behaviour of the refresh-token lifecycle: hashing at rest, rotation,
 * reuse detection (family revocation), expiry and logout.
 */
public class RefreshTokenServiceTest {

    private RefreshTokenRepository repository;
    private UserRepository userRepository;
    private JwtService jwtService;
    private RefreshTokenService service;

    @BeforeMethod
    public void setUp() {
        repository = mock(RefreshTokenRepository.class);
        userRepository = mock(UserRepository.class);

        JwtProperties properties = new JwtProperties();
        properties.setSecret("unit-test-secret-that-is-at-least-32-bytes!!");
        properties.setExpirationMinutes(10);
        properties.setRefreshTokenDays(30);
        jwtService = new JwtService(properties);

        service = new RefreshTokenService(repository, userRepository, jwtService, properties);
        when(repository.save(any(RefreshToken.class))).thenAnswer(inv -> inv.getArgument(0));
    }

    private static User user() {
        User user = new User();
        user.setId(1L);
        user.setUsername("alice");
        user.setTokenVersion(5);
        return user;
    }

    private static RefreshToken storedToken(String rawToken, JwtService jwtService) {
        RefreshToken token = new RefreshToken();
        token.setTokenHash(jwtService.hashRefreshToken(rawToken));
        token.setFamilyId("family-0000");
        token.setUserId(1L);
        token.setExpiresAt(Instant.now().plusSeconds(3600));
        return token;
    }

    @Test
    public void issueStoresOnlyTheHashAndBindsTheAccessTokenVersion() throws Exception {
        RefreshTokenService.Issued issued = service.issue(user());

        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(repository).save(captor.capture());
        RefreshToken stored = captor.getValue();

        assertNotEquals(stored.getTokenHash(), issued.refreshToken(),
                "the plaintext refresh token must never hit the database");
        assertEquals(stored.getTokenHash(), jwtService.hashRefreshToken(issued.refreshToken()));
        assertEquals(stored.getFamilyId().length(), 36);
        assertNull(stored.getRotatedAt());
        assertNull(stored.getRevokedAt());

        JwtService.Validated access = jwtService.validate(issued.accessToken());
        assertEquals(access.username(), "alice");
        assertEquals(access.tokenVersion(), 5,
                "the access token must carry the user's current token version");
        assertTrue(issued.refreshToken().length() >= 40,
                "refresh token must be high-entropy");
    }

    @Test
    public void rotateMarksTheOldTokenAndIssuesAFreshOneInTheSameFamily() throws Exception {
        RefreshTokenService.Issued first = service.issue(user());
        ArgumentCaptor<RefreshToken> issueCaptor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(repository).save(issueCaptor.capture());
        RefreshToken storedFirst = issueCaptor.getValue();

        when(repository.findByTokenHash(storedFirst.getTokenHash()))
                .thenReturn(Optional.of(storedFirst));
        when(userRepository.findById(1L)).thenReturn(Optional.of(user()));

        RefreshTokenService.Issued second = service.rotate(first.refreshToken());

        assertNotNull(storedFirst.getRotatedAt(), "the presented token must be spent");
        assertNotEquals(second.refreshToken(), first.refreshToken(),
                "rotation must issue a new refresh token");

        ArgumentCaptor<RefreshToken> allSaves = ArgumentCaptor.forClass(RefreshToken.class);
        verify(repository, atLeast(2)).save(allSaves.capture());
        RefreshToken newest = allSaves.getAllValues().get(allSaves.getAllValues().size() - 1);
        assertEquals(newest.getFamilyId(), storedFirst.getFamilyId(),
                "the new token must stay in the same family");
        assertNotEquals(newest.getTokenHash(), storedFirst.getTokenHash());
        assertNotNull(jwtService.validate(second.accessToken()));
    }

    @Test
    public void reusingASpentTokenRevokesTheWholeFamily() throws Exception {
        RefreshToken spent = storedToken("raw-spent-token", jwtService);
        spent.setRotatedAt(Instant.now().minusSeconds(60));
        RefreshToken liveSibling = storedToken("raw-live-token", jwtService);
        liveSibling.setFamilyId(spent.getFamilyId());

        when(repository.findByTokenHash(spent.getTokenHash()))
                .thenReturn(Optional.of(spent));
        when(repository.findByFamilyId(spent.getFamilyId()))
                .thenReturn(List.of(spent, liveSibling));

        try {
            service.rotate("raw-spent-token");
            fail("replaying a spent refresh token must be rejected");
        } catch (InvalidTokenException expected) {
            assertTrue(expected.getMessage().contains("reuse"),
                    "the error must signal reuse detection: " + expected.getMessage());
        }

        assertNotNull(spent.getRevokedAt(), "the spent token must be revoked");
        assertNotNull(liveSibling.getRevokedAt(),
                "reuse detection must revoke the whole family — the token leaked");
        verify(userRepository, never()).save(any());
    }

    @Test
    public void expiredTokenIsRejectedAndRevoked() throws Exception {
        RefreshToken expired = storedToken("raw-expired-token", jwtService);
        expired.setExpiresAt(Instant.now().minusSeconds(1));
        when(repository.findByTokenHash(expired.getTokenHash()))
                .thenReturn(Optional.of(expired));

        try {
            service.rotate("raw-expired-token");
            fail("an expired refresh token must be rejected");
        } catch (InvalidTokenException expected) {
            assertTrue(expected.getMessage().contains("expired"));
        }
        assertNotNull(expired.getRevokedAt());
    }

    @Test(expectedExceptions = InvalidTokenException.class)
    public void unknownTokenIsRejected() throws Exception {
        when(repository.findByTokenHash(any())).thenReturn(Optional.empty());
        service.rotate("completely-unknown-token");
    }

    @Test
    public void logoutRevokesFamilyAndBumpsTokenVersion() throws Exception {
        RefreshToken current = storedToken("raw-logout-token", jwtService);
        User user = user();
        when(repository.findByTokenHash(current.getTokenHash()))
                .thenReturn(Optional.of(current));
        when(repository.findByFamilyId(current.getFamilyId()))
                .thenReturn(List.of(current));
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));

        service.revoke("raw-logout-token");

        assertNotNull(current.getRevokedAt(), "the family must be revoked");
        assertEquals(user.getTokenVersion(), 6,
                "logout must bump token_version so outstanding access JWTs die");
        verify(userRepository).save(user);
    }

    @Test
    public void logoutWithUnknownTokenIsSilentAndSideEffectFree() {
        when(repository.findByTokenHash(any())).thenReturn(Optional.empty());

        service.revoke("who-knows");   // must not throw

        verify(repository, never()).save(any());
        verify(userRepository, never()).save(any());
    }
}
