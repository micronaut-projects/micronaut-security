package io.micronaut.security.oauth2.endpoint.endsession.request;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.params.provider.Arguments.arguments;

@MicronautTest(startApplication = false)
class AuthorizationServerResolverTest {

    @Inject
    AuthorizationServerResolver resolver;

    static Stream<Arguments> paramsProvider() {
        return Stream.of(
                arguments("http://localhost:8180/auth/realms/master", AuthorizationServer.KEYCLOAK),
                arguments("https://dev-XXXXX.oktapreview.com/oauth2/default", AuthorizationServer.OKTA),
                arguments("https://cognito-idp.us-east-1.amazonaws.com/12345}/", AuthorizationServer.COGNITO),
                arguments("https://micronautguides.eu.auth0.com", AuthorizationServer.AUTH0),
                arguments("https://identity.oraclecloud.com/", AuthorizationServer.ORACLE_CLOUD));
    }

    @ParameterizedTest
    @MethodSource("paramsProvider")
    void inferAuthorizationServer(String issuer, AuthorizationServer authorizationServer) {
        assertTrue(resolver.resolve(issuer).isPresent());
        assertEquals(authorizationServer, resolver.resolve(issuer).get());
    }

    @Test
    void inferAuthorizationServerBasedOnTheIssuerUrlMayReturnEmptyOptional() {
        assertFalse(resolver.resolve("http://localhost:8180/auth").isPresent());
    }
}