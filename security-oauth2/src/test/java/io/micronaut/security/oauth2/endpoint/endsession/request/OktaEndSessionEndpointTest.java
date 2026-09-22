package io.micronaut.security.oauth2.endpoint.endsession.request;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.simple.SimpleHttpRequest;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.client.OpenIdClient;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider;
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that an Okta client whose discovery document lacks {@code end_session_endpoint} does not fail with a
 * {@link NullPointerException} (HTTP 500) when logging out.
 */
class OktaEndSessionEndpointTest {
    private static final String OPENID_CONFIG_WITHOUT_END_SESSION_ENDPOINT = """
            {"issuer":"https://dev-265911.oktapreview.com/oauth2/default",
            "authorization_endpoint":"https://dev-265911.oktapreview.com/oauth2/default/v1/authorize",
            "token_endpoint":"https://dev-265911.oktapreview.com/oauth2/default/v1/token",
            "userinfo_endpoint":"https://dev-265911.oktapreview.com/oauth2/default/v1/userinfo",
            "registration_endpoint":"https://dev-265911.oktapreview.com/oauth2/v1/clients",
            "jwks_uri":"https://dev-265911.oktapreview.com/oauth2/default/v1/keys",
            "response_types_supported":["code","id_token","code id_token","code token","id_token token","code id_token token"],
            "response_modes_supported":["query","fragment","form_post","okta_post_message"],
            "grant_types_supported":["authorization_code","implicit","refresh_token","password"],
            "subject_types_supported":["public"],
            "id_token_signing_alg_values_supported":["RS256"],
            "scopes_supported":["openid","profile","email","address","phone","offline_access"],
            "token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],
            "claims_supported":["iss","ver","sub","aud","iat","exp","jti","auth_time","amr","idp","nonce","name","email"],
            "code_challenge_methods_supported":["S256"],
            "introspection_endpoint":"https://dev-265911.oktapreview.com/oauth2/default/v1/introspect",
            "revocation_endpoint":"https://dev-265911.oktapreview.com/oauth2/default/v1/revoke",
            "request_parameter_supported":true
            }""";

    @Test
    void oktaConfigurationWithoutEndSessionEndpointDoesNotFail() {
        String nameQualifier = "okta";
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class,
                Map.of("spec.name", "OktaEndSessionEndpointTestAuthServer"))) {
            try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class,
                    Map.of("spec.name", "OktaEndSessionEndpointTest",
                            // with the default reject-not-found=true, the 404 below is rewritten as 403 for an authenticated user
                            "micronaut.security.reject-not-found", false,
                            "micronaut.security.oauth2.clients." + nameQualifier + ".openid.issuer", authServer.getURL().toString(),
                            "micronaut.security.oauth2.clients." + nameQualifier + ".client-secret", "yyy",
                            "micronaut.security.oauth2.clients." + nameQualifier + ".client-id", "xxx"
                    ))) {
                OpenIdClient openIdClient = server.getApplicationContext().getBean(OpenIdClient.class, Qualifiers.byName(nameQualifier));
                assertTrue(openIdClient.supportsEndSession());

                EndSessionEndpointResolver endSessionEndpointResolver = server.getApplicationContext().getBean(EndSessionEndpointResolver.class);
                OauthClientConfiguration oauthClientConfiguration = server.getApplicationContext().getBean(OauthClientConfiguration.class, Qualifiers.byName(nameQualifier));
                OpenIdProviderMetadata openIdProviderMetadata = server.getApplicationContext().getBean(OpenIdProviderMetadata.class);
                EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder = server.getApplicationContext().getBean(EndSessionCallbackUrlBuilder.class);
                Optional<EndSessionEndpoint> endSessionEndpointOptional = endSessionEndpointResolver.resolve(oauthClientConfiguration, openIdProviderMetadata, endSessionCallbackUrlBuilder);
                assertTrue(endSessionEndpointOptional.isPresent());
                EndSessionEndpoint endSessionEndpoint = endSessionEndpointOptional.get();
                assertInstanceOf(OktaEndSessionEndpoint.class, endSessionEndpoint);
                assertNull(openIdProviderMetadata.getEndSessionEndpoint());

                // the metadata has no end_session_endpoint: the URL cannot be determined, so null is returned instead of throwing
                HttpRequest<?> request = new SimpleHttpRequest<>(HttpMethod.GET, "/oauth/logout", Collections.emptyMap());
                Authentication authentication = Authentication.build("sherlock");
                assertNull(endSessionEndpoint.getUrl(request, authentication));

                // and the OpenID client does not produce an end session redirect
                Optional<MutableHttpResponse<?>> redirect = openIdClient.endSessionRedirect(request, authentication);
                assertFalse(redirect.isPresent());

                // the logout route responds gracefully (no redirect available -> empty Optional -> 404) instead of a 500 (NullPointerException)
                try (HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
                    HttpClientResponseException e = assertThrows(HttpClientResponseException.class, () ->
                            httpClient.toBlocking().exchange(HttpRequest.GET("/oauth/logout").basicAuth("sherlock", "elementary")));
                    assertEquals(HttpStatus.NOT_FOUND, e.getStatus());
                }
            }
        }
    }

    @Requires(property = "spec.name", value = "OktaEndSessionEndpointTest")
    @Singleton
    @Replaces(AuthorizationServerResolver.class)
    static class AuthorizationServerResolverReplacement implements AuthorizationServerResolver {
        @Override
        public Optional<AuthorizationServer> resolve(String issuer) {
            return Optional.of(AuthorizationServer.OKTA);
        }
    }

    @Requires(property = "spec.name", value = "OktaEndSessionEndpointTest")
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider<HttpRequest<?>, String, String> {
        AuthenticationProviderUserPassword() {
            super(List.of(new SuccessAuthenticationScenario("sherlock", Collections.emptyList(),
                    Map.of(OauthAuthenticationMapper.PROVIDER_KEY, "okta"))));
        }
    }

    @Requires(property = "spec.name", value = "OktaEndSessionEndpointTestAuthServer")
    @Controller
    static class OpenidConfigurationController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/.well-known/openid-configuration")
        String index() {
            return OPENID_CONFIG_WITHOUT_END_SESSION_ENDPOINT;
        }
    }
}
