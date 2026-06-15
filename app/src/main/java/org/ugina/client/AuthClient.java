package org.ugina.client;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;

public class AuthClient {private final String baseUrl;
    private final HttpClient httpClient;
    private final ObjectMapper mapper = new ObjectMapper();

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
        return (String) parsed.get("token");
    }

}
