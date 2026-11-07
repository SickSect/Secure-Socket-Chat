package org.ugina;

import io.jsonwebtoken.JwtException;
import org.testng.annotations.Test;
import org.ugina.auth.JwtService;
import org.ugina.config.JwtProperties;

import static org.testng.Assert.*;

public class JwtServiceTest {

    private static final String TEST_SECRET = "unit-test-secret-that-is-at-least-32-bytes!!";

    private JwtService service() {
        JwtProperties properties = new JwtProperties();
        properties.setSecret(TEST_SECRET);
        properties.setExpirationMinutes(10);
        properties.setRefreshTokenDays(30);
        return new JwtService(properties);
    }

    @Test
    public void roundtripCarriesUsernameAndTokenVersion() {
        JwtService service = service();
        String token = service.generate("alice", 7);

        JwtService.Validated validated = service.validate(token);
        assertEquals(validated.username(), "alice");
        assertEquals(validated.tokenVersion(), 7);
        assertEquals(service.validateAndGetUsername(token), "alice");
    }

    @Test
    public void legacyGenerateDefaultsToVersionOne() {
        JwtService service = service();
        JwtService.Validated validated = service.validate(service.generate("bob"));
        assertEquals(validated.username(), "bob");
        assertEquals(validated.tokenVersion(), 1,
                "tokens minted without the claim must be treated as version 1");
    }

    @Test(expectedExceptions = JwtException.class)
    public void garbageTokenIsRejected() {
        service().validate("not-a-jwt-at-all");
    }

    @Test(expectedExceptions = JwtException.class)
    public void tokenFromAnotherSecretIsRejected() {
        String token = service().generate("alice", 1);

        JwtProperties otherProps = new JwtProperties();
        otherProps.setSecret("a-completely-different-secret-of-32-bytes!!");
        otherProps.setExpirationMinutes(10);
        new JwtService(otherProps).validate(token);
    }

    @Test(expectedExceptions = JwtException.class)
    public void blankTokenIsRejected() {
        service().validate(" ");
    }

    @Test
    public void everyTokenIsUniqueEvenWithinTheSameSecond() {
        JwtService service = service();
        String first = service.generate("alice", 1);
        String second = service.generate("alice", 1);
        assertNotEquals(first, second,
                "the jti claim must make tokens unique — identical tokens are indistinguishable");
        assertNotEquals(service.generate("alice", 1), first);
    }

    @Test
    public void refreshTokenHashIsDeterministicKeyedHex() {
        JwtService service = service();
        String hashA = service.hashRefreshToken("raw-token-value");
        String hashAgain = service.hashRefreshToken("raw-token-value");
        String hashB = service.hashRefreshToken("another-token");

        assertEquals(hashA, hashAgain, "hashing must be deterministic");
        assertNotEquals(hashA, hashB);
        assertNotEquals(hashA, "raw-token-value", "the plaintext must not be stored");
        assertTrue(hashA.matches("[0-9a-f]{64}"), "expected64 hex chars, got: " + hashA);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void blankRefreshTokenCannotBeHashed() {
        service().hashRefreshToken("");
    }
}
