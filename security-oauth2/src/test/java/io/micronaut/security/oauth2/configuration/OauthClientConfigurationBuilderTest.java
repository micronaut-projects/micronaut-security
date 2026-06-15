package io.micronaut.security.oauth2.configuration;

import io.micronaut.http.MediaType;
import io.micronaut.security.oauth2.client.clientcredentials.ClientCredentialsConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.SecureEndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.TokenEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.endsession.request.AuthorizationServer;
import io.micronaut.security.oauth2.grants.GrantType;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class OauthClientConfigurationBuilderTest {

    @Test
    void builderCreatesOauthClientConfigurationBuilder() {
        OauthClientConfigurationBuilder builder = OauthClientConfiguration.builder();

        assertNotNull(builder);
        assertNotSame(builder, OauthClientConfiguration.builder());
    }

    @Test
    void builderMethodsReturnSameBuilder() {
        OauthClientConfigurationBuilder builder = OauthClientConfiguration.builder();

        assertSame(builder, builder.name("auth-server"));
        assertSame(builder, builder.clientId("client-id"));
        assertSame(builder, builder.clientSecret("client-secret"));
        assertSame(builder, builder.scopes("openid"));
        assertSame(builder, builder.enabled(false));
        assertSame(builder, builder.grantType(GrantType.PASSWORD));
        assertSame(builder, builder.token("https://auth.example.com/token"));
        assertSame(builder, builder.authorization("https://auth.example.com/authorize"));
        assertSame(builder, builder.clientCredentials());
        assertSame(builder, builder.introspection("https://auth.example.com/introspect"));
        assertSame(builder, builder.revocation("https://auth.example.com/revoke"));
        assertSame(builder, builder.authorizationServer(AuthorizationServer.MICROSOFT));
        assertSame(builder, builder.proxyWellKnownOauthAuthorizationServer(true));
        assertSame(builder, builder.proxyWellKnownOpenidConfiguration(true));
    }

    @Test
    void buildRequiresNameAndClientId() {
        NullPointerException missingName = assertThrows(NullPointerException.class, () ->
                OauthClientConfiguration.builder()
                        .clientId("client-id")
                        .build()
        );
        assertEquals("name", missingName.getMessage());

        NullPointerException missingClientId = assertThrows(NullPointerException.class, () ->
                OauthClientConfiguration.builder()
                        .name("auth-server")
                        .build()
        );
        assertEquals("clientId", missingClientId.getMessage());
    }

    @Test
    void buildsDefaultConfigurationWithRequiredValues() {
        OauthClientConfiguration configuration = OauthClientConfiguration.builder()
                .name("auth-server")
                .clientId("client-id")
                .build();

        assertTrue(configuration.isEnabled());
        assertEquals("auth-server", configuration.getName());
        assertEquals("client-id", configuration.getClientId());
        assertNull(configuration.getClientSecret());
        assertEquals(List.of(), configuration.getScopes());
        assertEquals(GrantType.AUTHORIZATION_CODE, configuration.getGrantType());
        assertFalse(configuration.getToken().isPresent());
        assertFalse(configuration.getAuthorization().isPresent());
        assertFalse(configuration.getClientCredentials().isPresent());
        assertFalse(configuration.getIntrospection().isPresent());
        assertFalse(configuration.getRevocation().isPresent());
        assertFalse(configuration.getOpenid().isPresent());
        assertNull(configuration.getAuthorizationServer());
        assertFalse(configuration.isProxyWellKnownOauthAuthorizationServer());
        assertFalse(configuration.isProxyWellKnownOpenidConfiguration());
    }

    @Test
    void buildCreatesImmutableSnapshot() {
        OauthClientConfigurationBuilder builder = OauthClientConfiguration.builder()
                .name("auth-server")
                .clientId("client-id")
                .scopes("openid");

        OauthClientConfiguration configuration = builder.build();
        builder.name("other-auth-server")
                .clientId("other-client-id")
                .scopes("email")
                .enabled(false)
                .grantType(GrantType.PASSWORD);

        assertEquals("auth-server", configuration.getName());
        assertEquals("client-id", configuration.getClientId());
        assertEquals(List.of("openid"), configuration.getScopes());
        assertTrue(configuration.isEnabled());
        assertEquals(GrantType.AUTHORIZATION_CODE, configuration.getGrantType());
        assertThrows(UnsupportedOperationException.class, () -> configuration.getScopes().add("email"));
        assertNotSame(builder, configuration);
    }

    @Test
    void buildsConfiguredOauthClientConfiguration() {
        OpenIdClientConfiguration openid = mock(OpenIdClientConfiguration.class);
        List<String> scopes = new ArrayList<>(List.of("openid", "profile"));

        OauthClientConfiguration configuration = OauthClientConfiguration.builder()
                .name("auth-server")
                .clientId("client-id")
                .clientSecret("client-secret")
                .scopes(scopes)
                .enabled(false)
                .grantType(GrantType.PASSWORD)
                .token("https://auth.example.com/token", "client_secret_basic", MediaType.APPLICATION_JSON_TYPE)
                .authorization("https://auth.example.com/authorize", "S256")
                .introspection("https://auth.example.com/introspect", "client_secret_post")
                .revocation("https://auth.example.com/revoke", "client_secret_post")
                .openid(openid)
                .authorizationServer(AuthorizationServer.MICROSOFT)
                .proxyWellKnownOauthAuthorizationServer(true)
                .proxyWellKnownOpenidConfiguration(true)
                .build();
        scopes.add("email");

        assertFalse(configuration.isEnabled());
        assertEquals("client-secret", configuration.getClientSecret());
        assertEquals(List.of("openid", "profile"), configuration.getScopes());
        assertThrows(UnsupportedOperationException.class, () -> configuration.getScopes().add("email"));
        assertEquals(GrantType.PASSWORD, configuration.getGrantType());

        SecureEndpointConfiguration token = configuration.getToken().orElseThrow();
        TokenEndpointConfiguration tokenEndpoint = assertInstanceOf(TokenEndpointConfiguration.class, token);
        assertEquals("https://auth.example.com/token", tokenEndpoint.getUrl().orElseThrow());
        assertEquals("client_secret_basic", tokenEndpoint.getAuthenticationMethod().orElseThrow());
        assertEquals(MediaType.APPLICATION_JSON_TYPE, tokenEndpoint.getContentType());

        assertEquals("https://auth.example.com/authorize", configuration.getAuthorization().orElseThrow().getUrl().orElseThrow());
        assertEquals("S256", configuration.getAuthorization().orElseThrow().getCodeChallengeMethod().orElseThrow());
        assertEquals("https://auth.example.com/introspect", configuration.getIntrospection().orElseThrow().getUrl().orElseThrow());
        assertEquals("client_secret_post", configuration.getIntrospection().orElseThrow().getAuthenticationMethod().orElseThrow());
        assertEquals("https://auth.example.com/revoke", configuration.getRevocation().orElseThrow().getUrl().orElseThrow());
        assertEquals("client_secret_post", configuration.getRevocation().orElseThrow().getAuthenticationMethod().orElseThrow());
        assertSame(openid, configuration.getOpenid().orElseThrow());
        assertEquals(AuthorizationServer.MICROSOFT, configuration.getAuthorizationServer());
        assertTrue(configuration.isProxyWellKnownOauthAuthorizationServer());
        assertTrue(configuration.isProxyWellKnownOpenidConfiguration());
    }

    @Test
    void clientCredentialsSelectsClientCredentialsGrant() {
        Map<String, String> additionalRequestParams = new HashMap<>(Map.of("audience", "https://api.example.com"));
        Duration advancedExpiration = Duration.ofMinutes(2);

        OauthClientConfiguration configuration = OauthClientConfiguration.builder()
                .name("auth-server")
                .clientId("client-id")
                .clientCredentials("read write", advancedExpiration, additionalRequestParams)
                .build();
        additionalRequestParams.put("resource", "https://resource.example.com");

        assertEquals(GrantType.CLIENT_CREDENTIALS, configuration.getGrantType());
        ClientCredentialsConfiguration clientCredentials = configuration.getClientCredentials().orElseThrow();
        assertTrue(clientCredentials.isEnabled());
        assertEquals("read write", clientCredentials.getScope().orElseThrow());
        assertEquals(advancedExpiration, clientCredentials.getAdvancedExpiration());
        assertEquals(Map.of("audience", "https://api.example.com"), clientCredentials.getAdditionalRequestParams());
        assertThrows(UnsupportedOperationException.class, () -> clientCredentials.getAdditionalRequestParams().put("resource", "https://resource.example.com"));
        assertFalse(clientCredentials.getHeaderPropagation().isPresent());
        assertNull(clientCredentials.getServiceIdPattern());
        assertNull(clientCredentials.getUriPattern());
    }
}
