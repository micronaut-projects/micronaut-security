package io.micronaut.security.token.jwt.cookie;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider;
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = "spec.name", value = "JwtCookieSameSiteInvalidTest")
@Property(name = "micronaut.http.client.follow-redirects", value = "false")
@Property(name = "micronaut.security.authentication", value = "cookie")
@Property(name = "micronaut.security.token.cookie.cookie-max-age", value = "5m")
@Property(name = "micronaut.security.token.cookie.cookie-same-site", value = "nonesense")
@Property(name = "micronaut.security.redirect.login-failure", value = "/login/authFailed")
@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "qrD6h8K6S9503Q06Y6Rfk21TErImPYqa")
@MicronautTest
class JwtCookieSameSiteInvalidTest {

    @Test
    void invalidSameSiteValueOmitsTheSameSiteAttribute(@Client("/") HttpClient httpClient) {
        HttpRequest<?> loginRequest = HttpRequest.POST("/login", Map.of("username", "sherlock", "password", "password"))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);

        List<String> cookies = httpClient.toBlocking().exchange(loginRequest, String.class).getHeaders().getAll("Set-Cookie");

        assertEquals(1, cookies.size());
        assertTrue(cookies.get(0).startsWith("JWT="));
        assertFalse(cookies.get(0).contains("SameSite"));
    }

    @Requires(property = "spec.name", value = "JwtCookieSameSiteInvalidTest")
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super(List.of(new SuccessAuthenticationScenario("sherlock")));
        }
    }
}
