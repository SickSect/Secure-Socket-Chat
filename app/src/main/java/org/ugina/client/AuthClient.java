package org.ugina.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;

public class AuthClient {private final String baseUrl;
    private final HttpClient httpClient;
    private final ObjectMapper mapper = new ObjectMapper();
    private String refreshToken;

    public AuthClient(String baseUrl) {
        this.baseUrl = baseUrl;
        this.httpClient = HttpClient.newHttpClient();
    }

    /**
     * Регистрирует нового пользователя.
     *
     * @return true если регистрация успешна (201)
     */
    public String register(String username, String password, String publicKeyBase64)
            throws Exception {
        String body = mapper.writeValueAsString(Map.of(
                "username", username,
                "password", password,
                "publicKey", publicKeyBase64
        ));

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/auth/register"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response = httpClient.send(
                request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 201) {
            return null;
        }
        // вернём тело целиком чтобы увидеть причину
        return "HTTP " + response.statusCode() + ": " + response.body();
    }

    /**
     * Логинится, возвращает JWT.
     *
     * @return JWT-строка или null если логин не удался
     */
    /**
     * Logs in and returns the access token (JWT).
     * The refresh token is stored internally for later use via refresh().
     *
     * @return JWT string, or null if login failed
     */
    public String login(String username, String password) throws Exception {
        String body = mapper.writeValueAsString(Map.of(
                "username", username,
                "password", password
        ));

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/auth/login"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response = httpClient.send(
                request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            return null;
        }

        Map<String, Object> parsed = mapper.readValue(response.body(), Map.class);
        this.refreshToken = (String) parsed.get("refreshToken");   // сохраняем refresh
        return (String) parsed.get("token");                       // возвращаем access как раньше
    }

    public String refresh() throws Exception {
        if (refreshToken == null)
            throw new IllegalStateException("No refresh token — login first");

        String body = mapper.writeValueAsString(Map.of("refreshToken", refreshToken));
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/auth/refresh"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response = httpClient.send(
                request, HttpResponse.BodyHandlers.ofString()
        );

        if (response.statusCode() == 401) {
            this.refreshToken = null;
            return null;
        }
        if (response.statusCode() != 200) {
            throw new Exception("Refresh failed: HTTP " + response.statusCode()
                    + " — " + response.body());
        }
        Map<String, Object> parsed = mapper.readValue(response.body(), Map.class);
        return (String) parsed.get("token");   // новый access token
    }

    public void logout() throws IOException, InterruptedException {
        if (refreshToken == null)
            return;
        String body = mapper.writeValueAsString(Map.of("refreshToken", refreshToken));
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/auth/logout"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        httpClient.send(
                request, HttpResponse.BodyHandlers.ofString()
        );
        this.refreshToken = null;
    }

    /**
     * @return the stored refresh token, or null if not logged in yet
     */
    public String getRefreshToken() {
        return refreshToken;
    }

}
