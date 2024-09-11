package io.micronaut.security.oauth2;

import io.micronaut.security.oauth2.configuration.endpoints.SecureEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.DefaultSecureEndpoint;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static io.micronaut.security.oauth2.endpoint.AuthenticationMethods.CLIENT_SECRET_BASIC;
import static io.micronaut.security.oauth2.endpoint.AuthenticationMethods.CLIENT_SECRET_POST;
import static org.junit.jupiter.api.Assertions.*;

class DefaultSecureEndpointTest {
    private static final Set<String> METHODS = Set.of("client_secret_basic",
            "client_secret_post",
            "client_secret_jwt",
            "private_key_jwt",
            "tls_client_auth",
            "self_signed_tls_client_auth");

    @Test
    void testGetAuthenticationMethodsSupported() {
        DefaultSecureEndpoint endpoint = new DefaultSecureEndpoint("http://localhost",  METHODS);
        Set<String> authenticationMethodsSupported = endpoint.getAuthenticationMethodsSupported();
        assertNotNull(authenticationMethodsSupported);
        assertEquals( METHODS, authenticationMethodsSupported);

        endpoint = new DefaultSecureEndpoint(new SecureEndpointConfiguration() {

            @Override
            public Optional<String> getAuthenticationMethod() {
                return Optional.of(CLIENT_SECRET_POST);
            }

            @Override
            public Optional<String> getUrl() {
                return Optional.of("http://localhost");
            }
        }, CLIENT_SECRET_BASIC);
        assertEquals("http://localhost", endpoint.getUrl());
        assertEquals(Set.of(CLIENT_SECRET_POST), endpoint.getAuthenticationMethodsSupported());

        endpoint = new DefaultSecureEndpoint(new SecureEndpointConfiguration() {
            @Override
            public Optional<String> getAuthenticationMethod() {
                return Optional.empty();
            }

            @Override
            public Optional<String> getUrl() {
                return Optional.of("http://localhost");
            }
        }, CLIENT_SECRET_BASIC);
        assertEquals("http://localhost", endpoint.getUrl());
        assertEquals(Set.of(CLIENT_SECRET_BASIC), endpoint.getAuthenticationMethodsSupported());
    }
}