package io.micronaut.security.supabase.auth;

import io.micronaut.context.annotation.Property;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.supabase.auth.SignupRequest;
import io.micronaut.supabase.auth.SupabaseAuthClient;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.test.support.TestPropertyProvider;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Bearer authentication mode backed by Supabase: login and refresh answer with the Supabase tokens.
 */
@Testcontainers(disabledWithoutDocker = true)
@Property(name = "micronaut.security.authentication", value = "bearer")
@MicronautTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SupabaseBearerAuthenticationTest implements TestPropertyProvider {
    private static final Argument<Map<String, Object>> MAP = Argument.mapOf(String.class, Object.class);
    private static final String EMAIL = "bearer-test@example.com";
    private static final String PASSWORD = "correct-horse-battery";

    @Inject
    SupabaseAuthClient supabase;

    @Inject
    @Client("/")
    HttpClient httpClient;

    private String userId;

    @Override
    public @NonNull Map<String, String> getProperties() {
        return Supabase.getProperties();
    }

    @BeforeAll
    void signUp() {
        Map<String, Object> session = supabase.signup(null, new SignupRequest(EMAIL, null, PASSWORD, null, null, null, null, null)).body();
        @SuppressWarnings("unchecked")
        Map<String, Object> user = (Map<String, Object>) session.get("user");
        userId = (String) user.get("id");
    }

    @Test
    void loginAnswersWithTheSupabaseTokens() {
        Map<String, Object> body = login();

        assertEquals(userId, body.get("username"));
        assertEquals(List.of("authenticated"), body.get("roles"));
        assertEquals("Bearer", body.get("token_type"));
        assertEquals(3600, body.get("expires_in"));
        String accessToken = (String) body.get("access_token");
        assertEquals(userId, claim(accessToken, "sub"), "access_token should be the Supabase JWT of the user");
        assertNotNull(body.get("refresh_token"));
    }

    @Test
    void wrongPasswordIsUnauthorized() {
        HttpClientResponseException e = assertThrows(HttpClientResponseException.class, () -> client().exchange(
            HttpRequest.POST("/login", Map.of("username", EMAIL, "password", "wrong-password")), MAP));

        assertEquals(HttpStatus.UNAUTHORIZED, e.getStatus());
    }

    @Test
    void refreshAnswersWithTheRotatedSupabaseTokens() {
        Map<String, Object> initial = login();

        HttpResponse<Map<String, Object>> response = client().exchange(HttpRequest.POST("/oauth/access_token",
            Map.of("grant_type", "refresh_token", "refresh_token", initial.get("refresh_token"))), MAP);

        assertEquals(HttpStatus.OK, response.getStatus());
        Map<String, Object> rotated = response.body();
        assertNotEquals(initial.get("refresh_token"), rotated.get("refresh_token"), "Supabase rotates the refresh token");
        assertEquals(userId, claim((String) rotated.get("access_token"), "sub"));
        assertEquals(3600, rotated.get("expires_in"));
    }

    private Map<String, Object> login() {
        return client().exchange(HttpRequest.POST("/login", Map.of("username", EMAIL, "password", PASSWORD)), MAP).body();
    }

    private BlockingHttpClient client() {
        return httpClient.toBlocking();
    }

    private static String claim(String jwt, String name) {
        String payload = new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]));
        String key = "\"" + name + "\":\"";
        int start = payload.indexOf(key) + key.length();
        return payload.substring(start, payload.indexOf('"', start));
    }
}
