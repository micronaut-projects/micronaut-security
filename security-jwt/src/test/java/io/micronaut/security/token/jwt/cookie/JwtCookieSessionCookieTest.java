package io.micronaut.security.token.jwt.cookie;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.provider.HttpRequestExecutorAuthenticationProvider;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;

@Property(name = "micronaut.http.client.followRedirects", value = StringUtils.FALSE)
@Property(name = "micronaut.security.authentication", value = "cookie")
@Property(name = "micronaut.security.token.cookie.session-cookie", value = StringUtils.TRUE)
@Property(name = "micronaut.security.redirect.login-failure", value = "/login/authFailed")
@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "qrD6h8K6S9503Q06Y6Rfk21TErImPYqa")
@Property(name = "spec.name", value = "JwtCookieSessionCookeTest")
@MicronautTest
class JwtCookieSessionCookieTest {

    @Test
    void testMaxAgeIsSetFromJwtCookieSettings(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> loginRequest = HttpRequest.POST("/login", Map.of("username","sherlock","password","password"))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);

        HttpResponse<?> loginRsp = client.exchange(loginRequest, String.class);

        String cookie = loginRsp.getHeaders().get("Set-Cookie");
        System.out.println(cookie);
        assertFalse(cookie.contains("Max-Age="));
        assertFalse(cookie.contains("Expires="));
    }

    @Requires(property = "spec.name", value = "JwtCookieSessionCookeTest")
    @Singleton
    static class AuthProvider<B> implements HttpRequestExecutorAuthenticationProvider<B> {

        @Override
        public AuthenticationResponse authenticate(HttpRequest<B> requestContext, AuthenticationRequest<String, String> authRequest) {
            return AuthenticationResponse.success("sherlock");
        }
    }

}
