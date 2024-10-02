package io.micronaut.security.oauth2.configuration;

import io.micronaut.context.annotation.Property;
import io.micronaut.security.oauth2.configuration.endpoints.SecureEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethod;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@Property(name = "micronaut.security.oauth2.clients.stravaold.scopes", value = "read")
@Property(name = "micronaut.security.oauth2.clients.stravaold.authorization.url", value = "https://www.strava.com/oauth/authorize")
@Property(name = "micronaut.security.oauth2.clients.stravaold.token.url", value = "https://www.strava.com/oauth/token")
@Property(name = "micronaut.security.oauth2.clients.stravaold.token.auth-method", value = "client_secret_post")
@Property(name = "micronaut.security.oauth2.clients.stravaold.client-id", value = "xxx")
@Property(name = "micronaut.security.oauth2.clients.stravaold.client-secret", value = "yyy")
@Property(name = "micronaut.security.oauth2.clients.stravanew.scopes", value = "read")
@Property(name = "micronaut.security.oauth2.clients.stravanew.authorization.url", value = "https://www.strava.com/oauth/authorize")
@Property(name = "micronaut.security.oauth2.clients.stravanew.token.url", value = "https://www.strava.com/oauth/token")
@Property(name = "micronaut.security.oauth2.clients.stravanew.token.authentication-method", value = "client_secret_post")
@Property(name = "micronaut.security.oauth2.clients.stravanew.client-id", value = "xxx")
@Property(name = "micronaut.security.oauth2.clients.stravanew.client-secret", value = "yyy")
@MicronautTest(startApplication = false)
class OauthClientConfigurationTest {

    @Inject
    @Named("stravaold")
    OauthClientConfiguration stravaOldConfiguration;

    @Inject
    @Named("stravanew")
    OauthClientConfiguration stravaNewConfiguration;


    @Test
    void deprecatedAuthMethodConfigurationIsStillSupported() {
        assertTrue(stravaOldConfiguration.getToken().isPresent());
        SecureEndpointConfiguration tokenEndpoint = stravaOldConfiguration.getToken().get();
        assertTrue(tokenEndpoint.getAuthenticationMethod().isPresent());
        assertEquals("client_secret_post", tokenEndpoint.getAuthenticationMethod().get());
        assertTrue(tokenEndpoint.getAuthMethod().isPresent());
        assertEquals(AuthenticationMethod.CLIENT_SECRET_POST, tokenEndpoint.getAuthMethod().get());

        assertTrue(stravaNewConfiguration.getToken().isPresent());
        SecureEndpointConfiguration tokenNewEndpoint = stravaNewConfiguration.getToken().get();
        assertTrue(tokenNewEndpoint.getAuthenticationMethod().isPresent());
        assertEquals("client_secret_post", tokenNewEndpoint.getAuthenticationMethod().get());
        assertTrue(tokenNewEndpoint.getAuthMethod().isPresent());
        assertEquals(AuthenticationMethod.CLIENT_SECRET_POST, tokenNewEndpoint.getAuthMethod().get());

    }

}