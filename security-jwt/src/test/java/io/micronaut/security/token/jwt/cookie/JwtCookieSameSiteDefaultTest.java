package io.micronaut.security.token.jwt.cookie;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider;
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario;
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent;
import io.micronaut.security.token.refresh.RefreshTokenPersistence;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = "spec.name", value = "JwtCookieSameSiteDefaultTest")
@Property(name = "micronaut.http.client.follow-redirects", value = "false")
@Property(name = "micronaut.security.authentication", value = "cookie")
@Property(name = "micronaut.security.token.cookie.cookie-max-age", value = "5m")
@Property(name = "micronaut.security.redirect.login-failure", value = "/login/authFailed")
@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "qrD6h8K6S9503Q06Y6Rfk21TErImPYqa")
@Property(name = "micronaut.security.token.jwt.generator.refresh-token.secret", value = "pleaseChangeThisSecretForANewOne")
@MicronautTest
class JwtCookieSameSiteDefaultTest {

    @Test
    void jwtAndRefreshTokenCookiesDefaultToSameSiteLax(@Client("/") HttpClient httpClient) {
        HttpRequest<?> loginRequest = HttpRequest.POST("/login", Map.of("username", "sherlock", "password", "password"))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);

        List<String> cookies = httpClient.toBlocking().exchange(loginRequest, String.class).getHeaders().getAll("Set-Cookie");

        assertEquals(2, cookies.size());
        assertTrue(cookies.stream().anyMatch(cookie -> cookie.startsWith("JWT=")));
        assertTrue(cookies.stream().anyMatch(cookie -> cookie.startsWith("JWT_REFRESH_TOKEN=")));
        assertTrue(cookies.stream().allMatch(cookie -> cookie.contains("SameSite=Lax")));
        assertTrue(cookies.stream().allMatch(cookie -> cookie.contains("HTTPOnly")));
    }

    @Requires(property = "spec.name", value = "JwtCookieSameSiteDefaultTest")
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super(List.of(new SuccessAuthenticationScenario("sherlock")));
        }
    }

    @Requires(property = "spec.name", value = "JwtCookieSameSiteDefaultTest")
    @Singleton
    static class InMemoryRefreshTokenPersistence implements RefreshTokenPersistence {

        private final Map<String, Authentication> tokens = new ConcurrentHashMap<>();

        @Override
        public void persistToken(RefreshTokenGeneratedEvent event) {
            tokens.put(event.getRefreshToken(), event.getAuthentication());
        }

        @Override
        public Publisher<Authentication> getAuthentication(String refreshToken) {
            return Publishers.just(tokens.get(refreshToken));
        }
    }
}
