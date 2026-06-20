package org.ugina;

import io.jsonwebtoken.JwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
import org.testng.annotations.Test;
import org.ugina.auth.JwtService;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

@SpringBootTest
public class JwtServiceTest extends AbstractTestNGSpringContextTests {

    @Autowired
    private JwtService jwtService;

    @Test
    public void generateAndValidateRoundTrip() {
        String token = jwtService.generate("alice");
        assertNotNull(token);

        String username = jwtService.validateAndGetUsername(token);
        assertEquals(username, "alice");
    }

    @Test
    public void tokenHasThreeParts() {
        String token = jwtService.generate("alice");
        // JWT = header.payload.signature
        assertEquals(token.split("\\.").length, 3,
                "JWT должен состоять из трёх частей");
    }

    @Test(expectedExceptions = JwtException.class)
    public void tamperedTokenRejected() {
        String token = jwtService.generate("alice");
        // Портим токен — меняем последний символ подписи
        String tampered = token.substring(0, token.length() - 1)
                + (token.endsWith("a") ? "b" : "a");
        jwtService.validateAndGetUsername(tampered);
    }

    @Test(expectedExceptions = JwtException.class)
    public void garbageTokenRejected() {
        jwtService.validateAndGetUsername("this.is.not.a.valid.jwt");
    }
}
