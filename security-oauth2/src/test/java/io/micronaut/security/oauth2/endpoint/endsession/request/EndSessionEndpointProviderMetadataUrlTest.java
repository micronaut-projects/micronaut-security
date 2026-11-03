package io.micronaut.security.oauth2.endpoint.endsession.request;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Property;
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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The end_session_endpoint advertised by an OpenID provider is used verbatim; it is never expanded as a URI template.
 */
class EndSessionEndpointProviderMetadataUrlTest {

    private static final String SPEC_NAME = "EndSessionEndpointProviderMetadataUrlTest";
    /**
     * On this branch the end session endpoint is inferred from the issuer, so the issuer path contains "okta" and the
     * Okta endpoint, which reads end_session_endpoint from the provider metadata, is used.
     */
    private static final String CLIENT = "okta";
    private static final String ISSUER_PATH = "/okta";
    private static final String HONEST_END_SESSION_ENDPOINT = "https://provider.example/oauth2/v2.0/logout?tenant=acme";
    private static final String MALICIOUS_END_SESSION_ENDPOINT = maliciousEndSessionEndpoint();

    @Test
    void endSessionEndpointWithQueryComponentIsPreserved() {
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class,
            authServerConfiguration(HONEST_END_SESSION_ENDPOINT))) {
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
            authServerConfiguration(MALICIOUS_END_SESSION_ENDPOINT))) {
            try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, serverConfiguration(authServer))) {
                assertNull(endSessionUrl(server));

                OpenIdClient openIdClient = server.getApplicationContext().getBean(OpenIdClient.class, Qualifiers.byName(CLIENT));
                Authentication authentication = Authentication.build("sherlock");
                HttpRequest<?> originating = new SimpleHttpRequest<>(HttpMethod.GET, "/oauth/logout", Collections.emptyMap());
                assertFalse(openIdClient.endSessionRedirect(originating, authentication).isPresent());
            }
        }
    }

    private static String maliciousEndSessionEndpoint() {
        StringBuilder url = new StringBuilder("https://provider.example/oauth2/v2.0/logout");
        for (int i = 0; i < 1000; i++) {
            url.append("{parameters}");
        }
        return url.toString();
    }

    private static Map<String, Object> authServerConfiguration(String endSessionEndpoint) {
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("spec.name", SPEC_NAME + "AuthServer");
        configuration.put("end-session-endpoint", endSessionEndpoint);
        return configuration;
    }

    private static Map<String, Object> serverConfiguration(EmbeddedServer authServer) {
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("spec.name", SPEC_NAME);
        configuration.put("micronaut.security.oauth2.clients." + CLIENT + ".openid.issuer", authServer.getURL() + ISSUER_PATH);
        configuration.put("micronaut.security.oauth2.clients." + CLIENT + ".client-secret", "test-fixture-not-a-secret");
        configuration.put("micronaut.security.oauth2.clients." + CLIENT + ".client-id", "test-client-id");
        return configuration;
    }

    private static String endSessionUrl(EmbeddedServer server) {
        ApplicationContext context = server.getApplicationContext();
        OpenIdClient openIdClient = context.getBean(OpenIdClient.class, Qualifiers.byName(CLIENT));
        assertTrue(openIdClient.supportsEndSession());
        EndSessionEndpointResolver endSessionEndpointResolver = context.getBean(EndSessionEndpointResolver.class);
        OauthClientConfiguration oauthClientConfiguration = context.getBean(OauthClientConfiguration.class, Qualifiers.byName(CLIENT));
        OpenIdProviderMetadata openIdProviderMetadata = context.getBean(OpenIdProviderMetadata.class);
        EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder = context.getBean(EndSessionCallbackUrlBuilder.class);
        Optional<EndSessionEndpoint> endSessionEndpoint = endSessionEndpointResolver.resolve(oauthClientConfiguration, () -> openIdProviderMetadata, endSessionCallbackUrlBuilder);
        assertTrue(endSessionEndpoint.isPresent());
        Authentication authentication = Authentication.build("sherlock");
        return endSessionEndpoint.get().getUrl(new SimpleHttpRequest<>(HttpMethod.GET, "/oauth/logout", Collections.emptyMap()), authentication);
    }

    @Requires(property = "spec.name", value = SPEC_NAME + "AuthServer")
    @Controller(ISSUER_PATH)
    static class OpenidConfigurationController {

        private final String endSessionEndpoint;

        OpenidConfigurationController(@Property(name = "end-session-endpoint") String endSessionEndpoint) {
            this.endSessionEndpoint = endSessionEndpoint;
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/.well-known/openid-configuration")
        String index() {
            return "{"
                + "\"issuer\":\"https://provider.example/v2.0\","
                + "\"authorization_endpoint\":\"https://provider.example/oauth2/v2.0/authorize\","
                + "\"token_endpoint\":\"https://provider.example/oauth2/v2.0/token\","
                + "\"jwks_uri\":\"https://provider.example/discovery/v2.0/keys\","
                + "\"end_session_endpoint\":\"" + endSessionEndpoint + "\","
                + "\"response_types_supported\":[\"code\"],"
                + "\"subject_types_supported\":[\"pairwise\"],"
                + "\"id_token_signing_alg_values_supported\":[\"RS256\"]"
                + "}";
        }
    }
}
