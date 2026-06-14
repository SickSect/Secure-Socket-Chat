package org.ugina;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;
import org.ugina.auth.LocalAuthProvider;
import org.ugina.auth.UserPrincipal;
import org.ugina.auth.exceptions.InvalidTokenException;
import org.ugina.auth.exceptions.RegistrationException;
import org.ugina.crypto.RsaCrypto;
import org.ugina.repository.UserRepository;

import java.security.KeyPair;

import static org.testng.Assert.*;

@SpringBootTest
public class LocalAuthProviderTest extends AbstractTestNGSpringContextTests {

    @Autowired
    private LocalAuthProvider authProvider;

    @Autowired
    private UserRepository userRepository;

    private String validPublicKey() throws Exception {
        KeyPair pair = RsaCrypto.generateKeyPair();
        return RsaCrypto.publicKeyToBase64(pair.getPublic());
    }

    @AfterMethod
    public void cleanup() {
        userRepository.findByUsername("reg_test_user")
                .ifPresent(userRepository::delete);
    }

    @Test
    public void registerCreatesUser() throws Exception {
        UserPrincipal principal = authProvider.register(
                "reg_test_user", "password123", validPublicKey());

        assertEquals(principal.username(), "reg_test_user");
        assertTrue(userRepository.existsByUsername("reg_test_user"));
    }

    @Test
    public void registerHashesPassword() throws Exception {
        authProvider.register("reg_test_user", "password123", validPublicKey());

        var saved = userRepository.findByUsername("reg_test_user").orElseThrow();
        assertNotEquals(saved.getPasswordHash(), "password123",
                "пароль должен быть захеширован, не храниться в открытом виде");
        assertTrue(saved.getPasswordHash().startsWith("$2a$"),
                "должен быть BCrypt-хеш");
    }

    @Test(expectedExceptions = RegistrationException.class)
    public void registerRejectsDuplicateUsername() throws Exception {
        authProvider.register("reg_test_user", "password123", validPublicKey());
        // второй раз с тем же именем — должно упасть
        authProvider.register("reg_test_user", "otherpass", validPublicKey());
    }

    @Test(expectedExceptions = RegistrationException.class)
    public void registerRejectsInvalidPublicKey() throws Exception {
        authProvider.register("reg_test_user", "password123", "not-a-valid-key");
    }

    @Test
    public void validateAcceptsValidToken() throws Exception {
        // регистрируем + логинимся
        String pubKey = validPublicKey();
        authProvider.register("reg_test_user", "password123", pubKey);
        var token = authProvider.authenticate("reg_test_user", "password123");

        // валидируем токен
        UserPrincipal principal = authProvider.validate(token.value());

        assertEquals(principal.username(), "reg_test_user");
        assertEquals(principal.publicKey(), pubKey);
    }

    @Test(expectedExceptions = InvalidTokenException.class)
    public void validateRejectsGarbageToken() throws Exception {
        authProvider.validate("not.a.valid.token");
    }
}
