package io.micronaut.security.oauth2.endpoint.endsession.request;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.DefaultHttpClientConfiguration;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.simple.SimpleHttpRequest;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.filters.SecurityFilter;
import io.micronaut.security.oauth2.client.OpenIdClient;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * With {@code micronaut.security.authentication=idtoken} the {@code id_token_hint} sent to the Okta end session endpoint must be
 * the ID token which authenticated the request (the JWT cookie), never an unrelated token which happens to be present in the request,
 * such as the {@code Authorization: Bearer} header a gateway adds to every forwarded request.
 */
class OktaEndSessionEndpointTest {

    private static final String CLIENT_ID = "okta-client-id-test-fixture-not-a-secret";
    private static final String CLIENT_SECRET = "okta-client-secret-test-fixture-not-a-secret";
    private static final String END_SESSION_ENDPOINT = "https://dev-test-fixture.okta.com/oauth2/default/v1/logout";
    private static final String PARAM_ID_TOKEN_HINT = "id_token_hint";
    private static final String PARAM_POST_LOGOUT_REDIRECT_URI = "post_logout_redirect_uri";
    private static final String JWT_COOKIE = "JWT";
    private static final String ISSUER_PATH = "/okta";

    private static RSAKey providerKey;
    private static RSAKey gatewayKey;

    @BeforeAll
    static void generateKeys() throws JOSEException {
        providerKey = new RSAKeyGenerator(2048).keyID("provider-test-fixture").generate();
        gatewayKey = new RSAKeyGenerator(2048).keyID("gateway-test-fixture").generate();
    }

    @Test
    void idTokenHintIsTheIdTokenWhichAuthenticatedTheRequestNotTheBearerHeader() throws Exception {
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class,
            Collections.singletonMap("spec.name", "OktaEndSessionEndpointTestAuthServer"))) {
            authServer.getApplicationContext().getBean(OpenIdConfigurationController.class).setUrl(issuer(authServer));
            try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, relyingParty(authServer))) {

                OpenIdClient openIdClient = server.getApplicationContext().getBean(OpenIdClient.class, Qualifiers.byName("okta"));
                assertTrue(openIdClient.supportsEndSession());

                String idToken = signedJwt(providerKey, issuer(authServer), CLIENT_ID);
                String gatewayToken = signedJwt(gatewayKey, "https://gateway.example.com", "gateway-audience-test-fixture");
                String postLogoutRedirectUri = "http://localhost:" + server.getPort() + "/logout";

                DefaultHttpClientConfiguration configuration = new DefaultHttpClientConfiguration();
                configuration.setFollowRedirects(false);
                try (HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL(), configuration)) {

                    // a gateway adds its own bearer token: on this branch only the first token found in the request is
                    // validated and the bearer header is read before the cookie, so the request is not authenticated at all
                    // and no redirect carrying any token is produced
                    HttpClientResponseException rejected = assertThrows(HttpClientResponseException.class,
                        () -> httpClient.toBlocking().exchange(HttpRequest.GET("/oauth/logout")
                            .cookie(Cookie.of(JWT_COOKIE, idToken))
                            .bearerAuth(gatewayToken)));
                    assertEquals(HttpStatus.UNAUTHORIZED, rejected.getStatus());
                    String rejectedLocation = rejected.getResponse().getHeaders().get(HttpHeaders.LOCATION);
                    assertTrue(rejectedLocation == null || !rejectedLocation.contains(gatewayToken),
                        "the gateway bearer token must not be sent to the OpenID provider");

                    // accepted path: the user authenticates with the ID token cookie
                    HttpResponse<?> response = httpClient.toBlocking().exchange(HttpRequest.GET("/oauth/logout")
                        .cookie(Cookie.of(JWT_COOKIE, idToken)));
                    assertEquals(HttpStatus.FOUND, response.getStatus());
                    String location = response.getHeaders().get(HttpHeaders.LOCATION);
                    assertNotNull(location);
                    assertEquals(logoutUrl(idToken, postLogoutRedirectUri), URI.create(location));
                }
            }
        }
    }

    @Test
    @SuppressWarnings({"deprecation", "unchecked"})
    void deprecatedConstructorIgnoresTheTokenResolver() throws Exception {
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class,
            Collections.singletonMap("spec.name", "OktaEndSessionEndpointTestAuthServer"))) {
            authServer.getApplicationContext().getBean(OpenIdConfigurationController.class).setUrl(issuer(authServer));
            try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, relyingParty(authServer))) {
                ApplicationContext ctx = server.getApplicationContext();
                OauthClientConfiguration clientConfiguration = ctx.getBean(OauthClientConfiguration.class, Qualifiers.byName("okta"));
                OpenIdProviderMetadata providerMetadata = ctx.getBean(OpenIdProviderMetadata.class, Qualifiers.byName("okta"));
                OktaEndSessionEndpoint endpoint = new OktaEndSessionEndpoint(
                    ctx.getBean(EndSessionCallbackUrlBuilder.class),
                    clientConfiguration,
                    () -> providerMetadata,
                    ctx.getBean(io.micronaut.security.config.SecurityConfiguration.class),
                    ctx.getBean(io.micronaut.security.token.reader.TokenResolver.class));
                SimpleHttpRequest<?> request = new SimpleHttpRequest<>(HttpMethod.GET, "http://localhost:" + server.getPort() + "/logout", null);
                request.bearerAuth("gateway.token.value");
                String url = endpoint.getUrl(request, Authentication.build("sherlock"));
                assertFalse(url.contains(PARAM_ID_TOKEN_HINT));
                assertTrue(url.contains(PARAM_POST_LOGOUT_REDIRECT_URI));
            }
        }
    }

    @Test
    void tokenNotUsedToAuthenticateTheRequestIsNotSentAsIdTokenHint() throws Exception {
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class,
            Collections.singletonMap("spec.name", "OktaEndSessionEndpointTestAuthServer"))) {
            authServer.getApplicationContext().getBean(OpenIdConfigurationController.class).setUrl(issuer(authServer));
            try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, relyingParty(authServer))) {

                ApplicationContext ctx = server.getApplicationContext();
                EndSessionEndpointResolver resolver = ctx.getBean(EndSessionEndpointResolver.class);
                OauthClientConfiguration clientConfiguration = ctx.getBean(OauthClientConfiguration.class, Qualifiers.byName("okta"));
                OpenIdProviderMetadata providerMetadata = ctx.getBean(OpenIdProviderMetadata.class, Qualifiers.byName("okta"));
                EndSessionCallbackUrlBuilder callbackUrlBuilder = ctx.getBean(EndSessionCallbackUrlBuilder.class);
                Optional<EndSessionEndpoint> endSessionEndpointOptional = resolver.resolve(clientConfiguration, () -> providerMetadata, callbackUrlBuilder);
                assertTrue(endSessionEndpointOptional.isPresent());
                EndSessionEndpoint endSessionEndpoint = assertInstanceOf(OktaEndSessionEndpoint.class, endSessionEndpointOptional.get());

                String idToken = signedJwt(providerKey, issuer(authServer), CLIENT_ID);
                String gatewayToken = signedJwt(gatewayKey, "https://gateway.example.com", "gateway-audience-test-fixture");
                String postLogoutRedirectUri = "http://localhost:" + server.getPort() + "/logout";
                Authentication authentication = Authentication.build("sherlock");

                // rejected path: a bearer token is present in the request but no token authenticated the request
                SimpleHttpRequest<?> request = new SimpleHttpRequest<>(HttpMethod.GET, "/oauth/logout", null);
                request.bearerAuth(gatewayToken);
                String url = endSessionEndpoint.getUrl(request, authentication);
                assertNotNull(url);
                assertFalse(url.contains(gatewayToken));
                assertEquals(UriBuilder.of(END_SESSION_ENDPOINT).queryParam(PARAM_POST_LOGOUT_REDIRECT_URI, postLogoutRedirectUri).build(), URI.create(url));

                // accepted path: the token which authenticated the request is sent even if another token comes first in the request
                request = new SimpleHttpRequest<>(HttpMethod.GET, "/oauth/logout", null);
                request.bearerAuth(gatewayToken);
                request.setAttribute(SecurityFilter.TOKEN, idToken);
                url = endSessionEndpoint.getUrl(request, authentication);
                assertNotNull(url);
                assertEquals(logoutUrl(idToken, postLogoutRedirectUri), URI.create(url));

                // the ID token obtained during the authorization code flow has precedence
                String flowIdToken = signedJwt(providerKey, issuer(authServer), CLIENT_ID);
                url = endSessionEndpoint.getUrl(request, Authentication.build("sherlock", Collections.singletonMap("openIdToken", flowIdToken)));
                assertNotNull(url);
                assertEquals(logoutUrl(flowIdToken, postLogoutRedirectUri), URI.create(url));
            }
        }
    }

    private static String issuer(EmbeddedServer authServer) {
        return authServer.getURL() + ISSUER_PATH;
    }

    private static Map<String, Object> relyingParty(EmbeddedServer authServer) {
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("spec.name", "OktaEndSessionEndpointTest");
        configuration.put("micronaut.security.authentication", "idtoken");
        configuration.put("micronaut.security.oauth2.clients.okta.openid.issuer", issuer(authServer));
        configuration.put("micronaut.security.oauth2.clients.okta.client-secret", CLIENT_SECRET);
        configuration.put("micronaut.security.oauth2.clients.okta.client-id", CLIENT_ID);
        return configuration;
    }

    private static URI logoutUrl(String idToken, String postLogoutRedirectUri) {
        return UriBuilder.of(END_SESSION_ENDPOINT)
            .queryParam(PARAM_ID_TOKEN_HINT, idToken)
            .queryParam(PARAM_POST_LOGOUT_REDIRECT_URI, postLogoutRedirectUri)
            .build();
    }

    private static String signedJwt(RSAKey key, String issuer, String audience) throws JOSEException {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject("sherlock")
            .issuer(issuer)
            .audience(audience)
            .issueTime(new Date())
            .expirationTime(new Date(System.currentTimeMillis() + 5 * 60 * 1000))
            .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    /**
     * On this branch the authorization server is inferred from the issuer, so the issuer path contains "okta".
     */
    @Requires(property = "spec.name", value = "OktaEndSessionEndpointTestAuthServer")
    @Controller(ISSUER_PATH)
    static class OpenIdConfigurationController {
        private String url;

        void setUrl(String url) {
            this.url = url;
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/.well-known/openid-configuration")
        @Produces(MediaType.APPLICATION_JSON)
        String index() {
            return "{"
                + "\"issuer\": \"" + url + "\","
                + "\"authorization_endpoint\": \"" + url + "/oauth2/default/v1/authorize\","
                + "\"token_endpoint\": \"" + url + "/oauth2/default/v1/token\","
                + "\"userinfo_endpoint\": \"" + url + "/oauth2/default/v1/userinfo\","
                + "\"jwks_uri\": \"" + url + "/oauth2/default/v1/keys\","
                + "\"end_session_endpoint\": \"" + END_SESSION_ENDPOINT + "\","
                + "\"response_types_supported\": [\"code\"],"
                + "\"subject_types_supported\": [\"public\"],"
                + "\"id_token_signing_alg_values_supported\": [\"RS256\"],"
                + "\"scopes_supported\": [\"openid\", \"profile\", \"email\"],"
                + "\"token_endpoint_auth_methods_supported\": [\"client_secret_basic\", \"client_secret_post\"]"
                + "}";
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/oauth2/default/v1/keys")
        @Produces(MediaType.APPLICATION_JSON)
        String keys() {
            return new JWKSet(providerKey.toPublicJWK()).toString();
        }
    }
}
