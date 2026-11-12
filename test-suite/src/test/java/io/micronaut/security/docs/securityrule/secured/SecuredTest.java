package io.micronaut.security.docs.securityrule.secured;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.provider.HttpRequestAuthenticationProvider;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Property(name = "spec.name", value = "SecuredTest")
@MicronautTest
class SecuredTest {

    @Test
    void anonymousEndpointCanBeAccessedWithoutAuthentication(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        assertDoesNotThrow(() -> client.exchange(HttpRequest.GET("/example/anonymous")));
    }

    @Test
    void authenticatedEndpointRequiresAnAuthenticatedUser(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        Executable e = () -> client.exchange(HttpRequest.GET("/example/authenticated"));
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, e);
        assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
        assertDoesNotThrow(() -> client.exchange(HttpRequest.GET("/example/authenticated").basicAuth("user", "password")));
    }

    @Test
    void adminEndpointRequiresOneOfTheRoles(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        Executable e = () -> client.exchange(HttpRequest.GET("/example/admin"));
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, e);
        assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
        e = () -> client.exchange(HttpRequest.GET("/example/admin").basicAuth("user", "password"));
        ex = assertThrows(HttpClientResponseException.class, e);
        assertEquals(HttpStatus.FORBIDDEN, ex.getStatus());
        assertDoesNotThrow(() -> client.exchange(HttpRequest.GET("/example/admin").basicAuth("admin", "password")));
    }

    @Requires(property = "spec.name", value = "SecuredTest")
    @Singleton
    static class AuthenticationProviderUserPassword<B> implements HttpRequestAuthenticationProvider<B> {
        @Override
        public AuthenticationResponse authenticate(HttpRequest<B> requestContext, AuthenticationRequest<String, String> authRequest) {
            if (authRequest.getIdentity().equals("user")) {
                return AuthenticationResponse.success("user");
            }
            if (authRequest.getIdentity().equals("admin")) {
                return AuthenticationResponse.success("admin", List.of("ROLE_ADMIN"));
            }
            return AuthenticationResponse.failure(AuthenticationFailureReason.USER_NOT_FOUND);
        }
    }
}
