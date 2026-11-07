package org.ugina;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.ugina.auth.AuthToken;
import org.ugina.auth.JwtService;
import org.ugina.auth.LocalAuthProvider;
import org.ugina.auth.RefreshTokenService;
import org.ugina.auth.UserPrincipal;
import org.ugina.auth.exceptions.AuthenticationException;
import org.ugina.auth.exceptions.InvalidTokenException;
import org.ugina.auth.exceptions.RegistrationException;
import org.ugina.config.JwtProperties;
import org.ugina.entity.User;
import org.ugina.crypto.RsaCrypto;
import org.ugina.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

/**
 * Login wiring (access + refresh pair) and the token-version revocation check
 * that backs logout.
 */
public class LocalAuthProviderTest {

    private static final String PASSWORD = "correct horse battery staple";

    private UserRepository userRepository;
    private JwtService jwtService;
    private RefreshTokenService refreshTokenService;
    private LocalAuthProvider provider;
    private PasswordEncoder passwordEncoder;

    private User alice;

    @BeforeMethod
    public void setUp() {
        userRepository = mock(UserRepository.class);
        refreshTokenService = mock(RefreshTokenService.class);
        passwordEncoder = new BCryptPasswordEncoder();

        JwtProperties properties = new JwtProperties();
        properties.setSecret("unit-test-secret-that-is-at-least-32-bytes!!");
        properties.setExpirationMinutes(10);
        properties.setRefreshTokenDays(30);
        jwtService = new JwtService(properties);

        alice = new User();
        alice.setId(1L);
        alice.setUsername("alice");
        alice.setPasswordHash(passwordEncoder.encode(PASSWORD));
        alice.setPublicKey("public-key-placeholder");
        alice.setTokenVersion(3);

        provider = new LocalAuthProvider(
                userRepository, passwordEncoder, jwtService, refreshTokenService);
    }

    @Test
    public void loginReturnsTheFullTokenPair() throws Exception {
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(alice));
        when(refreshTokenService.issue(any(User.class))).thenReturn(
                new RefreshTokenService.Issued("minted-access", 123L, "minted-refresh", 456L));

        AuthToken token = provider.authenticate("alice", PASSWORD);

        assertEquals(token.value(), "minted-access");
        assertEquals(token.refreshToken(), "minted-refresh");
        assertEquals(token.expiresAt(), 123L);
        assertEquals(token.refreshExpiresAt(), 456L);
    }

    @Test(expectedExceptions = org.ugina.auth.exceptions.AuthenticationException.class)
    public void wrongPasswordDoesNotIssueTokens() throws Exception {
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(alice));
        provider.authenticate("alice", "wrong-password");
    }

    @Test
    public void validateAcceptsTokenWithCurrentVersion() throws Exception {
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(alice));
        String token = jwtService.generate("alice", alice.getTokenVersion());

        UserPrincipal principal = provider.validate(token);

        assertEquals(principal.username(), "alice");
        assertEquals(principal.publicKey(), "public-key-placeholder");
    }

    @Test
    public void validateRejectsTokenFromAnEarlierVersion() throws Exception {
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(alice));
        // Minted when token_version was2; the user has since been logged out
        // (version bumped to3).
        String staleToken = jwtService.generate("alice", 2);

        try {
            provider.validate(staleToken);
            fail("a stale-version token must be rejected");
        } catch (InvalidTokenException expected) {
            assertTrue(expected.getMessage().contains("revoked"),
                    "expected revocation error, got: " + expected.getMessage());
        }
    }

    @Test(expectedExceptions = InvalidTokenException.class)
    public void validateRejectsGarbage() throws Exception {
        provider.validate("definitely-not-a-jwt");
    }

    @Test(expectedExceptions = InvalidTokenException.class)
    public void validateRejectsTokenOfDeletedUser() throws Exception {
        when(userRepository.findByUsername("ghost")).thenReturn(Optional.empty());
        provider.validate(jwtService.generate("ghost", 1));
    }

    // ─── identity-key rotation (step-up) ───

    @Test
    public void rotateKeyReplacesThePublicKeyAfterPasswordRecheck() throws Exception {
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(alice));
        String newKey = RsaCrypto.publicKeyToBase64(
                RsaCrypto.generateKeyPair().getPublic());

        UserPrincipal updated = provider.rotateKey("alice", PASSWORD, newKey);

        assertEquals(updated.username(), "alice");
        assertEquals(updated.publicKey(), newKey);
        assertEquals(alice.getPublicKey(), newKey, "the stored key must change");
        verify(userRepository).save(alice);
    }

    @Test(expectedExceptions = AuthenticationException.class)
    public void rotateKeyRejectsWrongPassword() throws Exception {
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(alice));
        String newKey = RsaCrypto.publicKeyToBase64(
                RsaCrypto.generateKeyPair().getPublic());
        provider.rotateKey("alice", "wrong-password", newKey);
    }

    @Test
    public void failedPasswordCheckLeavesTheKeyUntouched() throws Exception {
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(alice));
        String original = alice.getPublicKey();
        String newKey = RsaCrypto.publicKeyToBase64(
                RsaCrypto.generateKeyPair().getPublic());

        try {
            provider.rotateKey("alice", "wrong-password", newKey);
            fail("wrong password must be rejected");
        } catch (AuthenticationException expected) {
            // expected
        }

        assertEquals(alice.getPublicKey(), original,
                "a failed rotation must not modify the key");
        verify(userRepository, never()).save(any(User.class));
    }

    @Test(expectedExceptions = RegistrationException.class)
    public void rotateKeyRejectsMalformedKey() throws Exception {
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(alice));
        provider.rotateKey("alice", PASSWORD, "definitely-not-an-rsa-key");
    }

    @Test(expectedExceptions = AuthenticationException.class)
    public void rotateKeyRejectsUnknownUser() throws Exception {
        when(userRepository.findByUsername("ghost")).thenReturn(Optional.empty());
        String newKey = RsaCrypto.publicKeyToBase64(
                RsaCrypto.generateKeyPair().getPublic());
        provider.rotateKey("ghost", PASSWORD, newKey);
    }
}
