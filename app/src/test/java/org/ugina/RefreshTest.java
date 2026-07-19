package org.ugina;

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
public class RefreshTest extends AbstractTestNGSpringContextTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    /**
     * Full happy path: register → login → use the returned refresh token
     * on /refresh → expect a fresh access token back.
     */
    @Test
    public void refreshWithValidTokenReturnsNewAccessToken() throws Exception {
        String username = "refresh_user_" + System.currentTimeMillis();
        String password = "password123";

        registerUser(username, password);
        String refreshToken = loginAndGetRefreshToken(username, password);

        String body = objectMapper.writeValueAsString(Map.of("refreshToken", refreshToken));

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andExpect(jsonPath("$.expiresAt").exists());
    }

    /**
     * A token that was never issued must be rejected with 401.
     */
    @Test
    public void refreshWithUnknownTokenReturnsUnauthorized() throws Exception {
        String body = objectMapper.writeValueAsString(
                Map.of("refreshToken", "this-token-does-not-exist"));

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isUnauthorized());
    }

    /**
     * A blank refresh token must fail validation with 400 (Bean Validation).
     */
    @Test
    public void refreshWithBlankTokenReturnsBadRequest() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of("refreshToken", ""));

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());
    }

    /**
     * The access token issued via /refresh should differ from... well, be a
     * usable non-empty token. (Sanity check the response shape.)
     */
    @Test
    public void refreshedAccessTokenIsNotBlank() throws Exception {
        String username = "refresh_user2_" + System.currentTimeMillis();
        String password = "password123";

        registerUser(username, password);
        String refreshToken = loginAndGetRefreshToken(username, password);

        String body = objectMapper.writeValueAsString(Map.of("refreshToken", refreshToken));

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty());
    }

    // --- helpers ---

    private void registerUser(String username, String password) throws Exception {
        String publicKey = generateTestPublicKey();
        String body = objectMapper.writeValueAsString(Map.of(
                "username", username,
                "password", password,
                "publicKey", publicKey));

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated());
    }

    /**
     * Generates a valid RSA public key in Base64 for registration in tests.
     */
    private String generateTestPublicKey() throws Exception {
        KeyPair keyPair = RsaCrypto.generateKeyPair();
        return RsaCrypto.publicKeyToBase64(keyPair.getPublic());
    }

    private String loginAndGetRefreshToken(String username, String password) throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "username", username,
                "password", password));

        String response = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        Map<?, ?> parsed = objectMapper.readValue(response, Map.class);
        return (String) parsed.get("refreshToken");
    }
}