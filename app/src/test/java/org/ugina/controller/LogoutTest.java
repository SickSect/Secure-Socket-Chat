package org.ugina.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
import org.springframework.test.web.servlet.MockMvc;
import org.testng.annotations.Test;
import org.ugina.crypto.RsaCrypto;

import java.security.KeyPair;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
public class LogoutTest extends AbstractTestNGSpringContextTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    /**
     * Logout should succeed (204) for a valid refresh token.
     */
    @Test
    public void logoutWithValidTokenReturnsNoContent() throws Exception {
        String username = "logout_user_" + System.currentTimeMillis();
        String password = "password123";

        registerUser(username, password);
        String refreshToken = loginAndGetRefreshToken(username, password);

        String body = objectMapper.writeValueAsString(Map.of("refreshToken", refreshToken));

        mockMvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isNoContent());
    }

    /**
     * After logout, the refresh token must no longer work on /refresh (revoked).
     */
    @Test
    public void refreshFailsAfterLogout() throws Exception {
        String username = "logout_user2_" + System.currentTimeMillis();
        String password = "password123";

        registerUser(username, password);
        String refreshToken = loginAndGetRefreshToken(username, password);

        // отзываем токен
        String logoutBody = objectMapper.writeValueAsString(Map.of("refreshToken", refreshToken));
        mockMvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(logoutBody))
                .andExpect(status().isNoContent());

        // теперь /refresh с тем же токеном должен вернуть 401
        String refreshBody = objectMapper.writeValueAsString(Map.of("refreshToken", refreshToken));
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshBody))
                .andExpect(status().isUnauthorized());
    }

    // --- helpers ---

    private void registerUser(String username, String password) throws Exception {
        KeyPair keyPair = RsaCrypto.generateKeyPair();
        String publicKey = RsaCrypto.publicKeyToBase64(keyPair.getPublic());
        String body = objectMapper.writeValueAsString(Map.of(
                "username", username,
                "password", password,
                "publicKey", publicKey));

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated());
    }

    private String loginAndGetRefreshToken(String username, String password) throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "username", username,
                "password", password));

        String response = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andReturn().getResponse().getContentAsString();

        Map<?, ?> parsed = objectMapper.readValue(response, Map.class);
        return (String) parsed.get("refreshToken");
    }
}