package org.ugina.client;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/**
 * REST client for the auth API. Keeps the access/refresh token pair and
 * refreshes the access token automatically shortly before it expires.
 */
public class AuthClient {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(15);
    /** Refresh this long before the access token actually expires. */
    private static final long REFRESH_MARGIN_MS = 30_000;

    private final String baseUrl;
    private final HttpClient httpClient;
    private final ObjectMapper mapper = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private volatile String accessToken;
    private volatile String refreshToken;
    private volatile long accessTokenExpiresAt;

    public AuthClient(String baseUrl) throws Exception {
        this.baseUrl = stripTrailingSlash(baseUrl);
        SSLContext ctx = TlsClientContextFactory.createDefaultContext();
        this.httpClient = HttpClient.newBuilder()
                .sslContext(ctx)
                .connectTimeout(CONNECT_TIMEOUT)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    /**
     * Registers a new user.
     *
     * @return null on success, otherwise a human-readable error
     */
    public String register(String username, String password, String publicKeyBase64)
            throws Exception {
        String body = mapper.writeValueAsString(Map.of(
                "username", username,
                "password", password,
                "publicKey", publicKeyBase64
        ));

        HttpResponse<String> response = postJson("/api/auth/register", body);
        if (response.statusCode() == 201) {
            return null;
        }
        return "HTTP " + response.statusCode() + ": " + response.body();
    }

    /**
     * Logs in and returns a short-lived access JWT, or null if authentication
     * failed. The refresh token is stored for {@link #getValidAccessToken()}.
     */
    public String login(String username, String password) throws Exception {
        String body = mapper.writeValueAsString(Map.of(
                "username", username,
                "password", password
        ));

        HttpResponse<String> response = postJson("/api/auth/login", body);
        if (response.statusCode() != 200) {
            return null;
        }

        Map<?, ?> parsed = mapper.readValue(response.body(), Map.class);
        String access = text(parsed.get("token"));
        storeTokens(access, text(parsed.get("refreshToken")), parsed.get("expiresAt"));
        return access;
    }

    /**
     * Returns a still-valid access token, rotating the refresh token first if
     * the access token is about to expire. Returns null when the session can
     * no longer be refreshed (user must log in again).
     */
    public synchronized String getValidAccessToken() throws Exception {
        if (accessToken == null) {
            return null;
        }
        if (System.currentTimeMillis() + REFRESH_MARGIN_MS >= accessTokenExpiresAt) {
            return refreshTokens() ? accessToken : null;
        }
        return accessToken;
    }

    /**
     * Exchanges the stored refresh token for a new pair (the old refresh
     * token is single-use on the server).
     *
     * @return true when a new pair was obtained
     */
    public synchronized boolean refreshTokens() throws Exception {
        if (refreshToken == null) {
            return false;
        }
        String body = mapper.writeValueAsString(Map.of("refreshToken", refreshToken));
        HttpResponse<String> response = postJson("/api/auth/refresh", body);
        if (response.statusCode() != 200) {
            clearTokens();
            return false;
        }

        Map<?, ?> parsed = mapper.readValue(response.body(), Map.class);
        String access = text(parsed.get("token"));
        String refresh = text(parsed.get("refreshToken"));
        if (access == null || refresh == null) {
            clearTokens();
            return false;
        }
        storeTokens(access, refresh, parsed.get("expiresAt"));
        return true;
    }

    /**
     * Revokes the refresh session on the server (which also invalidates the
     * access token immediately) and drops the local pair. Best effort and
     * idempotent.
     */
    public synchronized void logout() {
        String presented = refreshToken;
        clearTokens();
        if (presented == null) {
            return;
        }
        try {
            String body = mapper.writeValueAsString(Map.of("refreshToken", presented));
            postJson("/api/auth/logout", body);
        } catch (Exception ignored) {
            // The local session is already dropped; a failed revoke simply
            // lets the access token live out its remaining minutes.
        }
    }

    /**
     * Rotates this account's public identity key (step-up: live access token
     * plus password). The new key pair is generated locally by the caller —
     * only the public half is sent.
     *
     * @return null on success, otherwise a human-readable error
     */
    public String rotateKey(String password, String publicKeyBase64) throws Exception {
        String access = getValidAccessToken();
        if (access == null) {
            return "No valid session — log in again";
        }
        String body = mapper.writeValueAsString(Map.of(
                "password", password,
                "publicKey", publicKeyBase64
        ));
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/auth/rotate-key"))
                .timeout(REQUEST_TIMEOUT)
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + access)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response = httpClient.send(
                request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200) {
            return null;
        }
        return "HTTP " + response.statusCode() + ": " + response.body();
    }

    private void storeTokens(String access, String refresh, Object expiresAt) {
        this.accessToken = access;
        this.refreshToken = refresh;
        this.accessTokenExpiresAt = expiresAt instanceof Number number
                ? number.longValue()
                : 0L;
    }

    private void clearTokens() {
        this.accessToken = null;
        this.refreshToken = null;
        this.accessTokenExpiresAt = 0L;
    }

    private HttpResponse<String> postJson(String path, String body) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .timeout(REQUEST_TIMEOUT)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static String text(Object value) {
        return value instanceof String string ? string : null;
    }

    private static String stripTrailingSlash(String value) {
        String result = value == null || value.isBlank() ? "https://localhost:8443" : value.trim();
        while (result.endsWith("/")) {
            result = result.substring(0, result.length() - 1);
        }
        return result;
    }
}
