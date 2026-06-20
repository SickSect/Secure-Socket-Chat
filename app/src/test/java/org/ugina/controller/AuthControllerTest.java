package org.ugina.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.ugina.crypto.RsaCrypto;
import org.ugina.repository.UserRepository;

import java.security.KeyPair;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
public class AuthControllerTest extends AbstractTestNGSpringContextTests {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private UserRepository userRepository;

    private MockMvc mockMvc;

    @BeforeClass
    public void setup() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
    }

    @AfterMethod
    public void cleanup() {
        userRepository.findByUsername("ctrl_test_user")
                .ifPresent(userRepository::delete);
    }

    private String validPublicKey() throws Exception {
        KeyPair pair = RsaCrypto.generateKeyPair();
        return RsaCrypto.publicKeyToBase64(pair.getPublic());
    }

    @Test
    public void registerWithValidRequestReturns201() throws Exception {
        String body = """
                {
                  "username": "ctrl_test_user",
                  "password": "password123",
                  "publicKey": "%s"
                }
                """.formatted(validPublicKey());

        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content(body))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("registered"))
                .andExpect(jsonPath("$.username").value("ctrl_test_user"));

        // Проверяем что реально создан в БД
        org.testng.Assert.assertTrue(
                userRepository.existsByUsername("ctrl_test_user"));
    }

    @Test
    public void registerWithMissingFieldsReturns400() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_FAILED"));
    }

    @Test
    public void registerWithValidPayloadReturns200() throws Exception {
        String body = """
                    {
                  "username": "Alice",
                  "password": "password123",
                  "publicKey": "%s"
                }
                """.formatted(validPublicKey());
        mockMvc.perform(post("/api/auth/register")
                .contentType("application/json")
                .content(body))
                .andExpect(status().isCreated());
    }

    @Test
    public void registerWithShortPasswordReturns400() throws Exception {
        String body = """
                {
                  "username": "ctrl_test_user",
                  "password": "123",
                  "publicKey": "%s"
                }
                """.formatted(validPublicKey());

        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content(body))
                .andExpect(status().isBadRequest());
    }

    @Test
    public void registerDuplicateReturns409() throws Exception {
        String body = """
                {
                  "username": "ctrl_test_user",
                  "password": "password123",
                  "publicKey": "%s"
                }
                """.formatted(validPublicKey());

        // первая регистрация — успех
        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content(body))
                .andExpect(status().isCreated());

        // вторая с тем же именем — конфликт
        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content(body))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("REGISTRATION_FAILED"));
    }
}