package io.micronaut.security.oauth2.configuration;

import io.micronaut.context.annotation.Property;
import io.micronaut.security.oauth2.configuration.endpoints.SecureEndpointConfiguration;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import org.junit.jupiter.api.Test;

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
    void deprecatedAuthMethodConfigurationIsStillSupported() {

        assertTrue(stravaNewConfiguration.getToken().isPresent());
        SecureEndpointConfiguration tokenNewEndpoint = stravaNewConfiguration.getToken().get();
        assertTrue(tokenNewEndpoint.getAuthenticationMethod().isPresent());
        assertEquals("client_secret_post", tokenNewEndpoint.getAuthenticationMethod().get());
    }

}
