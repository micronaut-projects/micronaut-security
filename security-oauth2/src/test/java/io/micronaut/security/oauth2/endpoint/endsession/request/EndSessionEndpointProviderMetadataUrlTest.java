package io.micronaut.security.oauth2.endpoint.endsession.request;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.simple.SimpleHttpRequest;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.client.OpenIdClient;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The end_session_endpoint advertised by an OpenID provider is used verbatim; it is never expanded as a URI template.
 */
class EndSessionEndpointProviderMetadataUrlTest {

    private static final String SPEC_NAME = "EndSessionEndpointProviderMetadataUrlTest";
    private static final String CLIENT = "microsoft";
    private static final String HONEST_END_SESSION_ENDPOINT = "https://provider.example/oauth2/v2.0/logout?tenant=acme";
    private static final String MALICIOUS_END_SESSION_ENDPOINT = "https://provider.example/oauth2/v2.0/logout" + "{parameters}".repeat(1000);

    @Test
    void endSessionEndpointWithQueryComponentIsPreserved() {
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class,
            Map.of("spec.name", SPEC_NAME + "AuthServer",
                "end-session-endpoint", HONEST_END_SESSION_ENDPOINT))) {
            try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, serverConfiguration(authServer))) {
                String url = endSessionUrl(server);
                assertEquals("https://provider.example/oauth2/v2.0/logout?tenant=acme&post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A" + server.getPort() + "%2Flogout", url);
            }
        }
    }

    @Test
    @Timeout(30)
    void endSessionEndpointIsNotExpandedAsUriTemplate() {
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class,
            Map.of("spec.name", SPEC_NAME + "AuthServer",
                "end-session-endpoint", MALICIOUS_END_SESSION_ENDPOINT))) {
            try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, serverConfiguration(authServer))) {
                assertNull(endSessionUrl(server));

                OpenIdClient openIdClient = server.getApplicationContext().getBean(OpenIdClient.class, Qualifiers.byName(CLIENT));
                Authentication authentication = Authentication.build("sherlock");
                HttpRequest<?> originating = new SimpleHttpRequest<>(HttpMethod.GET, "/oauth/logout", Collections.emptyMap());
                assertTrue(openIdClient.endSessionRedirect(originating, authentication).isEmpty());
            }
        }
    }

    private static Map<String, Object> serverConfiguration(EmbeddedServer authServer) {
        return Map.of("spec.name", SPEC_NAME,
            "micronaut.security.oauth2.clients." + CLIENT + ".openid.issuer", authServer.getURL().toString(),
            "micronaut.security.oauth2.clients." + CLIENT + ".client-secret", "test-fixture-not-a-secret",
            "micronaut.security.oauth2.clients." + CLIENT + ".client-id", "test-client-id");
    }

    private static String endSessionUrl(EmbeddedServer server) {
        ApplicationContext context = server.getApplicationContext();
        OpenIdClient openIdClient = context.getBean(OpenIdClient.class, Qualifiers.byName(CLIENT));
        assertTrue(openIdClient.supportsEndSession());
        EndSessionEndpointResolver endSessionEndpointResolver = context.getBean(EndSessionEndpointResolver.class);
        OauthClientConfiguration oauthClientConfiguration = context.getBean(OauthClientConfiguration.class, Qualifiers.byName(CLIENT));
        OpenIdProviderMetadata openIdProviderMetadata = context.getBean(OpenIdProviderMetadata.class);
        EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder = context.getBean(EndSessionCallbackUrlBuilder.class);
        Optional<EndSessionEndpoint> endSessionEndpoint = endSessionEndpointResolver.resolve(oauthClientConfiguration, openIdProviderMetadata, endSessionCallbackUrlBuilder);
        assertTrue(endSessionEndpoint.isPresent());
        Authentication authentication = Authentication.build("sherlock");
        return endSessionEndpoint.get().getUrl(new SimpleHttpRequest<>(HttpMethod.GET, "/oauth/logout", Collections.emptyMap()), authentication);
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    @Replaces(AuthorizationServerResolver.class)
    static class AuthorizationServerResolverReplacement implements AuthorizationServerResolver {
        @Override
        public Optional<AuthorizationServer> resolve(String issuer) {
            return Optional.of(AuthorizationServer.MICROSOFT);
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME + "AuthServer")
    @Controller
    static class OpenidConfigurationController {

        private final String endSessionEndpoint;

        OpenidConfigurationController(@Property(name = "end-session-endpoint") String endSessionEndpoint) {
            this.endSessionEndpoint = endSessionEndpoint;
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/.well-known/openid-configuration")
        String index() {
            return """
                {
                 "issuer":"https://provider.example/v2.0",
                 "authorization_endpoint":"https://provider.example/oauth2/v2.0/authorize",
                 "token_endpoint":"https://provider.example/oauth2/v2.0/token",
                 "jwks_uri":"https://provider.example/discovery/v2.0/keys",
                 "end_session_endpoint":"%s",
                 "response_types_supported":["code"],
                 "subject_types_supported":["pairwise"],
                 "id_token_signing_alg_values_supported":["RS256"]
                }
                """.formatted(endSessionEndpoint);
        }
    }
}
