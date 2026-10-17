package io.micronaut.supabase.auth;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.endpoints.SignupController;
import io.micronaut.security.handlers.SignupHandler;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.test.support.TestPropertyProvider;
import jakarta.annotation.PreDestroy;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.MalformedURLException;
import java.net.URI;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises {@link SignupController} against a real Supabase Auth (GoTrue) server
 * started with Testcontainers. See <a href="https://github.com/supabase/auth">supabase/auth</a>.
 */
@Testcontainers(disabledWithoutDocker = true)
@Property(name = "spec.name", value = "SignupControllerTest")
@MicronautTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SignupControllerTest implements TestPropertyProvider {
    private static final Argument<Map<String, Object>> MAP_ARGUMENT = Argument.mapOf(String.class, Object.class);

    @Override
    public @NonNull Map<String, String> getProperties() {
        return Supabase.getProperties();
    }

    private static final String SPEC_NAME = "SignupControllerTest";

    @Test
    void signupWithEmailAndPasswordReturnsSupabaseSession(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        Map<String, Object> body = Map.of("email", "alice@example.com", "password", "correct-horse-battery");

        HttpResponse<Map<String, Object>> response = client.exchange(HttpRequest.POST("/signup", body), MAP_ARGUMENT);

        Assertions.assertEquals(HttpStatus.OK, response.getStatus());
        Map<String, Object> session = response.body();
        assertNotNull(session);
        assertEquals("bearer", session.get("token_type"));
        String accessToken = (String) session.get("access_token");
        assertNotNull(accessToken);
        assertTrue(accessToken.split("\\.").length == 3, "access_token should be a JWT");
        String payload = new String(Base64.getUrlDecoder().decode(accessToken.split("\\.")[1]));
        assertTrue(payload.contains("\"aud\":\"authenticated\""), payload);
        assertTrue(payload.contains("\"email\":\"alice@example.com\""), payload);

        @SuppressWarnings("unchecked")
        Map<String, Object> user = (Map<String, Object>) session.get("user");
        assertNotNull(user);
        assertEquals("alice@example.com", user.get("email"));
        assertNotNull(user.get("id"));
    }

    @Test
    void signupWithTooShortPasswordIsRejected(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        Map<String, Object> body = Map.of("email", "bob@example.com", "password", "123");

        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(HttpRequest.POST("/signup", body), MAP_ARGUMENT));

        Assertions.assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, ex.getStatus());
        Map<String, Object> error = ex.getResponse().getBody(MAP_ARGUMENT).orElseThrow();
        assertEquals("weak_password", error.get("error_code"));
    }

    @Test
    void signupWithAlreadyRegisteredEmailIsRejected(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        Map<String, Object> body = Map.of("email", "carol@example.com", "password", "correct-horse-battery");
        Assertions.assertEquals(HttpStatus.OK, client.exchange(HttpRequest.POST("/signup", body), MAP_ARGUMENT).getStatus());

        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(HttpRequest.POST("/signup", body), MAP_ARGUMENT));

        Assertions.assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, ex.getStatus());
        Map<String, Object> error = ex.getResponse().getBody(MAP_ARGUMENT).orElseThrow();
        assertEquals("user_already_exists", error.get("error_code"));
    }

    /**
     * A {@link SignupHandler} that forwards the signup body to Supabase Auth's {@code POST /signup}
     * and relays the upstream status and body back to the caller.
     */
    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class SupabaseSignupHandler implements SignupHandler<HttpRequest<?>, HttpResponse<?>> {

        private final HttpClient supabaseClient;

        SupabaseSignupHandler(@Property(name = Supabase.SUPABASE_URL_PROPERTY) String supabaseUrl) throws MalformedURLException {
            this.supabaseClient = HttpClient.create(URI.create(supabaseUrl).toURL());
        }

        @Override
        public HttpResponse<?> signup(HttpRequest<?> request, Map<String, Object> body) {
            try {
                HttpResponse<Map<String, Object>> upstream = supabaseClient.toBlocking()
                    .exchange(HttpRequest.POST("/signup", body), MAP_ARGUMENT);
                return HttpResponse.status(upstream.getStatus()).body(upstream.body());
            } catch (HttpClientResponseException e) {
                return HttpResponse.status(e.getStatus()).body(e.getResponse().getBody(MAP_ARGUMENT).orElse(null));
            }
        }

        @PreDestroy
        void close() {
            supabaseClient.close();
        }
    }
}
