package org.ugina.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.ugina.auth.LocalAuthProvider;
import org.ugina.crypto.RsaCrypto;
import org.ugina.repository.UserRepository;

import java.security.KeyPair;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
public class LoginTest extends AbstractTestNGSpringContextTests {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private LocalAuthProvider authProvider;

    @Autowired
    private UserRepository userRepository;

    private MockMvc mockMvc;

    @BeforeClass
    public void setup() throws Exception {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();

        // Создаём тестового пользователя один раз
        KeyPair pair = RsaCrypto.generateKeyPair();
        String pubKey = RsaCrypto.publicKeyToBase64(pair.getPublic());
        authProvider.register("login_test_user", "correct_password", pubKey);
    }

    @AfterClass
    public void teardown() {
        userRepository.findByUsername("login_test_user")
                .ifPresent(userRepository::delete);
    }

    @Test
    public void loginWithCorrectCredentialsReturnsToken() throws Exception {
        String body = """
            {
              "username": "login_test_user",
              "password": "correct_password"
            }
            """;

        mockMvc.perform(post("/api/auth/login")
                        .contentType("application/json")
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andExpect(jsonPath("$.expiresAt").exists());
    }

    @Test
    public void loginWithWrongPasswordReturns401() throws Exception {
        String body = """
            {
              "username": "login_test_user",
              "password": "wrong_password"
            }
            """;

        mockMvc.perform(post("/api/auth/login")
                        .contentType("application/json")
                        .content(body))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("AUTHENTICATION_FAILED"));
    }

    @Test
    public void loginWithUnknownUserReturns401() throws Exception {
        String body = """
            {
              "username": "nonexistent_xyz",
              "password": "any_password"
            }
            """;

        mockMvc.perform(post("/api/auth/login")
                        .contentType("application/json")
                        .content(body))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void loginWithMissingFieldsReturns400() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType("application/json")
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }


}
