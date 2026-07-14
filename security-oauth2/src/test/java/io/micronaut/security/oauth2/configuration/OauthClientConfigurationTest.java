package io.micronaut.security.oauth2.configuration;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.exceptions.BeanInstantiationException;
import io.micronaut.security.oauth2.configuration.endpoints.SecureEndpointConfiguration;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

@Property(name = "micronaut.security.oauth2.clients.stravanew.scopes", value = "read")
@Property(name = "micronaut.security.oauth2.clients.stravanew.authorization.url", value = "https://www.strava.com/oauth/authorize")
@Property(name = "micronaut.security.oauth2.clients.stravanew.token.url", value = "https://www.strava.com/oauth/token")
@Property(name = "micronaut.security.oauth2.clients.stravanew.token.authentication-method", value = "client_secret_post")
@Property(name = "micronaut.security.oauth2.clients.stravanew.client-id", value = "xxx")
@Property(name = "micronaut.security.oauth2.clients.stravanew.client-secret", value = "yyy")
@MicronautTest(startApplication = false)
class OauthClientConfigurationTest {
    @Inject
    @Named("stravanew")
    OauthClientConfiguration stravaNewConfiguration;

    @Test
    void authorizationServerDefaultsToNull() {
        assertNull(stravaNewConfiguration.getAuthorizationServer());
    }

    @Test
    void testDefaultIsProxyWellKnownOpenidConfiguration() {
        assertFalse(stravaNewConfiguration.isProxyWellKnownOpenidConfiguration());
    }

    @Test
    void testDefaultIsProxyWellKnownOauthAuthorizationServer() {
        assertFalse(stravaNewConfiguration.isProxyWellKnownOauthAuthorizationServer());
    }

    @Test
    void deprecatedAuthMethodConfigurationIsStillSupported() {

        assertTrue(stravaNewConfiguration.getToken().isPresent());
        SecureEndpointConfiguration tokenNewEndpoint = stravaNewConfiguration.getToken().get();
        assertTrue(tokenNewEndpoint.getAuthenticationMethod().isPresent());
        assertEquals("client_secret_post", tokenNewEndpoint.getAuthenticationMethod().get());
    }

    @Test
    void validTokenEndpointUrlIsAccepted() {
        assertEquals("https://www.strava.com/oauth/token", stravaNewConfiguration.getTokenEndpoint().getUrl());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "example.com/oauth/token",
        "https:/example.com/oauth/token",
        "/oauth/token",
        "ftp://example.com/oauth/token"
    })
    void tokenEndpointUrlMustBeAbsoluteHttpUrl(String url) {
        assertInvalidTokenEndpointUrl(url);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("endpointConfigurationProperties")
    void endpointConfigurationUrlMustBeAbsoluteHttpUrl(String configurationType, String property) {
        assertInvalidOauthClientProperty(property, "ftp://example.com/oauth/endpoint");
    }

    @Test
    void openIdJwksUriMustBeAnAbsoluteHttpUrl() {
        assertInvalidOauthClientProperty("openid.jwks-uri", "ftp://example.com/oauth/jwks");
    }

    private static Stream<Arguments> endpointConfigurationProperties() {
        return Stream.of(
            Arguments.of("AuthorizationEndpointConfigurationProperties", "authorization.url"),
            Arguments.of("IntrospectionEndpointConfigurationProperties", "introspection.url"),
            Arguments.of("RevocationEndpointConfigurationProperties", "revocation.url"),
            Arguments.of("RegistrationEndpointConfigurationProperties", "openid.registration.url"),
            Arguments.of("UserInfoEndpointConfigurationProperties", "openid.user-info.url"),
            Arguments.of("OpenIdClientConfigurationProperties.AuthorizationEndpointConfigurationProperties", "openid.authorization.url"),
            Arguments.of("OpenIdClientConfigurationProperties.TokenEndpointConfigurationProperties", "openid.token.url"),
            Arguments.of("EndSessionConfigurationProperties", "openid.end-session.url")
        );
    }

    private void assertInvalidTokenEndpointUrl(String url) {
        assertInvalidOauthClientProperty("token.url", url);
    }

    private void assertInvalidOauthClientProperty(String property, String value) {
        BeanInstantiationException exception = assertThrows(BeanInstantiationException.class, () -> ApplicationContext.run(Map.of(
                "micronaut.security.oauth2.clients.invalid." + property, value,
                "micronaut.security.oauth2.clients.invalid.client-id", "xxx",
                "micronaut.security.oauth2.clients.invalid.client-secret", "yyy")));

        assertTrue(exception.getMessage().contains("must be a valid URL"));
    }

}
