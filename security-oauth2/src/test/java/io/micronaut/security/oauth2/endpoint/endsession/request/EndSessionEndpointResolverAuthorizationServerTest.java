package io.micronaut.security.oauth2.endpoint.endsession.request;

import io.micronaut.context.annotation.Property;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@Property(name = "micronaut.security.oauth2.clients.myauthserver.authorization-server", value = "KEYCLOAK")
@MicronautTest(startApplication = false)
class EndSessionEndpointResolverAuthorizationServerTest {

    @Test
    void returnsConfiguredAuthorizationServerWhenSetViaConfiguration(AuthorizationServerResolver resolver, OauthClientConfiguration config) {
        AuthorizationServer result = EndSessionEndpointResolver.authorizationServer(
            resolver,
            config,
            "https://micronautguides.eu.auth0.com"
        );
        assertEquals(AuthorizationServer.KEYCLOAK, result);
        assertEquals(AuthorizationServer.KEYCLOAK, config.getAuthorizationServer());
    }


    @Test
    void returnsConfiguredAuthorizationServerWhenPresent(AuthorizationServerResolver resolver) {
        OauthClientConfiguration config = mock(OauthClientConfiguration.class);
        when(config.getAuthorizationServer()).thenReturn(AuthorizationServer.KEYCLOAK);
        AuthorizationServer result = EndSessionEndpointResolver.authorizationServer(
            resolver,
            config,
            "https://micronautguides.eu.auth0.com"
        );
        assertEquals(AuthorizationServer.KEYCLOAK, result);
    }

    @Test
    void resolvesAuthorizationServerViaResolverWhenNotConfigured(AuthorizationServerResolver resolver) {
        OauthClientConfiguration config = mock(OauthClientConfiguration.class);
        when(config.getAuthorizationServer()).thenReturn(null);
        AuthorizationServer result = EndSessionEndpointResolver.authorizationServer(
            resolver,
            config,
            "https://micronautguides.eu.auth0.com"
        );
        assertEquals(AuthorizationServer.AUTH0, result);
    }

    @Test
    void returnsNullWhenResolverDoesNotResolveAnything(AuthorizationServerResolver resolver) {
        OauthClientConfiguration config = mock(OauthClientConfiguration.class);
        when(config.getAuthorizationServer()).thenReturn(null);
        AuthorizationServer result = EndSessionEndpointResolver.authorizationServer(
            resolver,
            config,
            "https://auth.micronautguides.com"
        );
        assertNull(result);
    }
}
