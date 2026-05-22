package io.micronaut.security.oauth2.configuration;

import io.micronaut.context.annotation.Property;
import io.micronaut.security.oauth2.configuration.endpoints.SecureEndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.TokenEndpointConfiguration;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import java.time.Duration;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@Property(name = "micronaut.security.oauth2.clients.stravanew.scopes", value = "read")
@Property(name = "micronaut.security.oauth2.clients.stravanew.authorization.url", value = "https://www.strava.com/oauth/authorize")
@Property(name = "micronaut.security.oauth2.clients.stravanew.token.url", value = "https://www.strava.com/oauth/token")
@Property(name = "micronaut.security.oauth2.clients.stravanew.token.authentication-method", value = "client_secret_post")
@Property(name = "micronaut.security.oauth2.clients.stravanew.token.client-assertion.lifetime", value = "PT2M")
@Property(name = "micronaut.security.oauth2.clients.stravanew.token.client-assertion.audience", value = "https://www.strava.com/oauth/token")
@Property(name = "micronaut.security.oauth2.clients.stravanew.token.client-assertion.signing-algorithm", value = "HS384")
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
    void clientAssertionConfigurationIsBound() {
        assertTrue(stravaNewConfiguration.getToken().isPresent());
        SecureEndpointConfiguration tokenNewEndpoint = stravaNewConfiguration.getToken().get();
        assertInstanceOf(TokenEndpointConfiguration.class, tokenNewEndpoint);
        TokenEndpointConfiguration tokenEndpointConfiguration = (TokenEndpointConfiguration) tokenNewEndpoint;
        assertTrue(tokenEndpointConfiguration.getClientAssertion().isPresent());
        assertEquals(Duration.ofMinutes(2), tokenEndpointConfiguration.getClientAssertion().get().getLifetime());
        assertEquals("https://www.strava.com/oauth/token", tokenEndpointConfiguration.getClientAssertion().get().getAudience().orElseThrow());
        assertEquals("HS384", tokenEndpointConfiguration.getClientAssertion().get().getSigningAlgorithm().orElseThrow());
    }

}
