package io.micronaut.security.oauth2;

import io.micronaut.security.oauth2.configuration.endpoints.SecureEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethod;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethods;
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
            public Optional<AuthenticationMethod> getAuthMethod() {
                return Optional.of(AuthenticationMethod.CLIENT_SECRET_POST);
            }

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
            public Optional<AuthenticationMethod> getAuthMethod() {
                return Optional.empty();
            }

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

    @Deprecated(forRemoval = true)
    @Test
    void testSupportedAuthenticationMethods() {
        String url = "http://localhost";
        List<AuthenticationMethod> methods = null;
        DefaultSecureEndpoint endpoint = new DefaultSecureEndpoint(url, methods);
        assertEquals(url, endpoint.getUrl());

        endpoint = new DefaultSecureEndpoint("http://localhost", List.of(AuthenticationMethod.CLIENT_SECRET_BASIC,
                AuthenticationMethod.CLIENT_SECRET_POST,
                AuthenticationMethod.CLIENT_SECRET_JWT,
                AuthenticationMethod.PRIVATE_KEY_JWT,
                AuthenticationMethod.TLS_CLIENT_AUTH));
        assertTrue(endpoint.getAuthenticationMethodsSupported().contains(AuthenticationMethod.CLIENT_SECRET_BASIC.toString()));
        assertTrue(endpoint.getAuthenticationMethodsSupported().contains(AuthenticationMethod.CLIENT_SECRET_POST.toString()));
        assertTrue(endpoint.getAuthenticationMethodsSupported().contains(AuthenticationMethod.CLIENT_SECRET_JWT.toString()));
        assertTrue(endpoint.getAuthenticationMethodsSupported().contains(AuthenticationMethod.PRIVATE_KEY_JWT.toString()));
        assertTrue(endpoint.getAuthenticationMethodsSupported().contains(AuthenticationMethod.TLS_CLIENT_AUTH.toString()));

        Optional<List<AuthenticationMethod>> authenticationMethodsSupportedOptional = endpoint.getSupportedAuthenticationMethods();
        assertTrue(authenticationMethodsSupportedOptional.isPresent());
        List<AuthenticationMethod> authMethods = authenticationMethodsSupportedOptional.get();
        assertEquals(METHODS.size() - 1, authMethods.size()); // self_signed_tls_client_auth is not a valid AuthenticationMethod
        assertTrue(authMethods.contains(AuthenticationMethod.CLIENT_SECRET_BASIC));
        assertTrue(authMethods.contains(AuthenticationMethod.CLIENT_SECRET_POST));
        assertTrue(authMethods.contains(AuthenticationMethod.CLIENT_SECRET_JWT));
        assertTrue(authMethods.contains(AuthenticationMethod.PRIVATE_KEY_JWT));
        assertTrue(authMethods.contains(AuthenticationMethod.TLS_CLIENT_AUTH));


        endpoint = new DefaultSecureEndpoint("http://localhost", METHODS);
        authenticationMethodsSupportedOptional = endpoint.getSupportedAuthenticationMethods();
        assertTrue(authenticationMethodsSupportedOptional.isPresent());
        authMethods = authenticationMethodsSupportedOptional.get();
        assertEquals(METHODS.size() - 1, authMethods.size()); // self_signed_tls_client_auth is not a valid AuthenticationMethod
        assertTrue(authMethods.contains(AuthenticationMethod.CLIENT_SECRET_BASIC));
        assertTrue(authMethods.contains(AuthenticationMethod.CLIENT_SECRET_POST));
        assertTrue(authMethods.contains(AuthenticationMethod.CLIENT_SECRET_JWT));
        assertTrue(authMethods.contains(AuthenticationMethod.PRIVATE_KEY_JWT));
        assertTrue(authMethods.contains(AuthenticationMethod.TLS_CLIENT_AUTH));
    }
}