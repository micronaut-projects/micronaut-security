package io.micronaut.security.oauth2;

import io.micronaut.security.oauth2.endpoint.AuthenticationMethod;
import io.micronaut.security.oauth2.endpoint.DefaultSecureEndpoint;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
        Optional<Set<String>> authenticationMethodsSupportedOptional = endpoint.getAuthenticationMethodsSupported();
        assertTrue(authenticationMethodsSupportedOptional.isPresent());
        assertEquals( METHODS, authenticationMethodsSupportedOptional.get());
    }

    @Deprecated(forRemoval = true)
    @Test
    void testSupportedAuthenticationMethods() {
        DefaultSecureEndpoint endpoint = new DefaultSecureEndpoint("http://localhost", METHODS);
        Optional<List<AuthenticationMethod>> authenticationMethodsSupportedOptional = endpoint.getSupportedAuthenticationMethods();
        assertTrue(authenticationMethodsSupportedOptional.isPresent());
        List<AuthenticationMethod> authMethods = authenticationMethodsSupportedOptional.get();
        assertEquals(METHODS.size() - 1, authMethods.size()); // self_signed_tls_client_auth is not a valid AuthenticationMethod
        assertTrue(authMethods.contains(AuthenticationMethod.CLIENT_SECRET_BASIC));
        assertTrue(authMethods.contains(AuthenticationMethod.CLIENT_SECRET_POST));
        assertTrue(authMethods.contains(AuthenticationMethod.CLIENT_SECRET_JWT));
        assertTrue(authMethods.contains(AuthenticationMethod.PRIVATE_KEY_JWT));
        assertTrue(authMethods.contains(AuthenticationMethod.TLS_CLIENT_AUTH));
    }
}