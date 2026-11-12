package io.micronaut.security.supabase.auth;

import io.micronaut.context.annotation.Property;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.test.support.TestPropertyProvider;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * In cookie authentication mode with {@code micronaut.security.redirect.enabled} set to {@code false},
 * {@link SupabaseSignupHandler} answers JSON instead of redirecting, as the cookie login handler does.
 */
@Testcontainers(disabledWithoutDocker = true)
@Property(name = "spec.name", value = "SupabaseCookieSignupWithoutRedirectsTest")
@Property(name = "micronaut.security.authentication", value = "cookie")
@Property(name = "micronaut.security.redirect.enabled", value = "false")
@Property(name = "micronaut.http.client.follow-redirects", value = "false")
@MicronautTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SupabaseCookieSignupWithoutRedirectsTest implements TestPropertyProvider {
    private static final Argument<Map<String, Object>> MAP_ARGUMENT = Argument.mapOf(String.class, Object.class);

    @Inject
    @Client("/")
    HttpClient httpClient;

    @Override
    public @NonNull Map<String, String> getProperties() {
        return Supabase.getProperties();
    }

    @Test
    void signupAnswersTheSupabaseSession() {
        HttpResponse<Map<String, Object>> response = httpClient.toBlocking().exchange(signup("grace@example.com", Supabase.TEST_PASSWORD), MAP_ARGUMENT);

        assertEquals(HttpStatus.OK, response.getStatus());
        assertNotNull(response.body());
        assertNotNull(response.body().get("access_token"));
    }

    @Test
    void rejectedSignupAnswersTheSupabaseError() {
        HttpClientResponseException e = assertThrows(HttpClientResponseException.class,
            () -> httpClient.toBlocking().exchange(signup("heidi@example.com", "123"), MAP_ARGUMENT));

        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, e.getStatus());
        assertEquals("weak_password", e.getResponse().getBody(MAP_ARGUMENT).orElseThrow().get("error_code"));
    }

    private static HttpRequest<?> signup(String email, String password) {
        return HttpRequest.POST("/signup", Map.of("email", email, "password", password))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
    }
}
