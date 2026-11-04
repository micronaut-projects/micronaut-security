package io.micronaut.security.oauth2.routes;

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
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Header;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.DefaultHttpClientConfiguration;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.server.util.HttpHostResolver;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.oauth2.endpoint.endsession.request.AuthorizationServer;
import io.micronaut.security.oauth2.endpoint.endsession.request.AuthorizationServerResolver;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.Claims;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * With {@code micronaut.security.authentication=idtoken} the attributes of the authentication are the claims of the ID token
 * which authenticated the request, and {@code /oauth/logout} trusts the {@code oauth2Provider} attribute set by the application
 * to pick the provider whose end session endpoint receives the token as {@code id_token_hint}. An ID token carrying an
 * {@code oauth2Provider} (or {@code openIdToken}) claim must therefore not authenticate at all, while the binding the
 * {@code UserInfo} token validator establishes for an opaque token must be kept even if the UserInfo response names another
 * provider's issuer.
 */
class EndSessionProviderClaimTest {

    private static final String SPEC_NAME = "EndSessionProviderClaimTest";
    private static final String PROVIDER_SPEC_NAME = "EndSessionProviderClaimTestProvider";
    private static final String ISSUER_PATH = "/oauth2/default";
    private static final String CLIENT_ONE_ID = "client-one-id-test-fixture-not-a-secret";
    private static final String CLIENT_TWO_ID = "client-two-id-test-fixture-not-a-secret";
    private static final String CLIENT_SECRET = "client-secret-test-fixture-not-a-secret";
    private static final String OPAQUE_TOKEN = "opaque-access-token-test-fixture-not-a-secret";
    private static final String PARAM_ID_TOKEN_HINT = "id_token_hint";
    private static final String PARAM_POST_LOGOUT_REDIRECT_URI = "post_logout_redirect_uri";
    private static final String JWT_COOKIE = "JWT";

    private static RSAKey providerOneKey;
    private static RSAKey providerTwoKey;

    @BeforeAll
    static void generateKeys() throws JOSEException {
        providerOneKey = new RSAKeyGenerator(2048).keyID("provider-one-test-fixture").generate();
        providerTwoKey = new RSAKeyGenerator(2048).keyID("provider-two-test-fixture").generate();
    }

    @Test
    void providerClaimOfTheIdTokenDoesNotChooseTheEndSessionEndpoint() throws Exception {
        try (EmbeddedServer providerOne = startProvider(providerOneKey);
             EmbeddedServer providerTwo = startProvider(providerTwoKey);
             EmbeddedServer server = startRelyingParty(providerOne, providerTwo)) {
            String postLogoutRedirectUri = "http://localhost:" + server.getPort() + "/logout";
            try (HttpClient httpClient = client(server)) {
                BlockingHttpClient client = httpClient.toBlocking();

                // rejected paths: an ID token carrying a claim named after an attribute only the application sets does not authenticate
                assertUnauthorized(client, signedIdToken(providerOneKey, issuer(providerOne), CLIENT_ONE_ID, Map.of(OauthAuthenticationMapper.PROVIDER_KEY, "two")));
                assertUnauthorized(client, signedIdToken(providerOneKey, issuer(providerOne), CLIENT_ONE_ID, Map.of(OauthAuthenticationMapper.PROVIDER_KEY, "one")));
                assertUnauthorized(client, signedIdToken(providerOneKey, issuer(providerOne), CLIENT_ONE_ID, Map.of(OpenIdAuthenticationMapper.OPENID_TOKEN_KEY, "chosen-by-the-provider")));

                // accepted path: the token is sent to the end session endpoint of the client it was issued to
                String idToken = signedIdToken(providerOneKey, issuer(providerOne), CLIENT_ONE_ID, Map.of());
                assertEquals(logoutUrl(providerOne, idToken, postLogoutRedirectUri), URI.create(logoutLocation(client, idToken)));
                idToken = signedIdToken(providerTwoKey, issuer(providerTwo), CLIENT_TWO_ID, Map.of());
                assertEquals(logoutUrl(providerTwo, idToken, postLogoutRedirectUri), URI.create(logoutLocation(client, idToken)));
            }
        }
    }

    @Test
    void userInfoResponseNamingAnotherIssuerDoesNotChangeTheEndSessionEndpoint() throws Exception {
        try (EmbeddedServer providerOne = startProvider(providerOneKey);
             EmbeddedServer providerTwo = startProvider(providerTwoKey);
             // an opaque token is only sent to a UserInfo endpoint when that client opts in, see UserInfoClientTokenValidator
             EmbeddedServer server = startRelyingParty(providerOne, providerTwo,
                 Map.of("micronaut.security.oauth2.clients.two.openid.user-info.validate-opaque-tokens", true))) {
            // provider two accepts the opaque token at its UserInfo endpoint and answers with provider one's issuer and client id
            ProviderController two = provider(providerTwo);
            two.acceptedUserInfoToken = OPAQUE_TOKEN;
            two.userInfoClaims = Map.of(
                Claims.SUBJECT, "sherlock",
                Claims.ISSUER, issuer(providerOne),
                Claims.AUDIENCE, CLIENT_ONE_ID);
            String postLogoutRedirectUri = "http://localhost:" + server.getPort() + "/logout";
            try (HttpClient httpClient = client(server)) {
                String location = logoutLocation(httpClient.toBlocking(), OPAQUE_TOKEN);
                assertFalse(location.startsWith(endSessionEndpoint(providerOne)),
                    "the token must not be sent to the provider named by the UserInfo response");
                assertEquals(logoutUrl(providerTwo, OPAQUE_TOKEN, postLogoutRedirectUri), URI.create(location));
            }
        }
    }

    private static String logoutLocation(BlockingHttpClient client, String token) {
        HttpResponse<?> response = client.exchange(HttpRequest.GET("/oauth/logout").cookie(Cookie.of(JWT_COOKIE, token)));
        assertEquals(HttpStatus.FOUND, response.getStatus());
        String location = response.getHeaders().get(HttpHeaders.LOCATION);
        assertNotNull(location);
        return location;
    }

    private static void assertUnauthorized(BlockingHttpClient client, String token) {
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(HttpRequest.GET("/oauth/logout").cookie(Cookie.of(JWT_COOKIE, token))));
        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatus());
    }

    private static HttpClient client(EmbeddedServer server) {
        DefaultHttpClientConfiguration configuration = new DefaultHttpClientConfiguration();
        configuration.setFollowRedirects(false);
        return server.getApplicationContext().createBean(HttpClient.class, server.getURL(), configuration);
    }

    private static EmbeddedServer startRelyingParty(EmbeddedServer providerOne, EmbeddedServer providerTwo) {
        return startRelyingParty(providerOne, providerTwo, Map.of());
    }

    private static EmbeddedServer startRelyingParty(EmbeddedServer providerOne, EmbeddedServer providerTwo, Map<String, Object> extra) {
        Map<String, Object> configuration = new HashMap<>(extra);
        configuration.putAll(Map.of(
            "spec.name", SPEC_NAME,
            "micronaut.security.authentication", "idtoken",
            "micronaut.security.redirect.enabled", StringUtils.FALSE,
            "micronaut.security.oauth2.clients.one.openid.issuer", issuer(providerOne),
            "micronaut.security.oauth2.clients.one.client-id", CLIENT_ONE_ID,
            "micronaut.security.oauth2.clients.one.client-secret", CLIENT_SECRET,
            "micronaut.security.oauth2.clients.two.openid.issuer", issuer(providerTwo),
            "micronaut.security.oauth2.clients.two.client-id", CLIENT_TWO_ID,
            "micronaut.security.oauth2.clients.two.client-secret", CLIENT_SECRET));
        return ApplicationContext.run(EmbeddedServer.class, configuration);
    }

    private static EmbeddedServer startProvider(RSAKey key) {
        EmbeddedServer provider = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", PROVIDER_SPEC_NAME));
        provider(provider).key = key;
        return provider;
    }

    private static ProviderController provider(EmbeddedServer provider) {
        return provider.getApplicationContext().getBean(ProviderController.class);
    }

    private static String issuer(EmbeddedServer provider) {
        return provider.getURL() + ISSUER_PATH;
    }

    private static String endSessionEndpoint(EmbeddedServer provider) {
        return issuer(provider) + "/v1/logout";
    }

    private static URI logoutUrl(EmbeddedServer provider, String idToken, String postLogoutRedirectUri) {
        return UriBuilder.of(endSessionEndpoint(provider))
            .queryParam(PARAM_ID_TOKEN_HINT, idToken)
            .queryParam(PARAM_POST_LOGOUT_REDIRECT_URI, postLogoutRedirectUri)
            .build();
    }

    private static String signedIdToken(RSAKey key, String issuer, String audience, Map<String, String> extraClaims) throws JOSEException {
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
            .subject("sherlock")
            .issuer(issuer)
            .audience(audience)
            .issueTime(new Date())
            .expirationTime(new Date(System.currentTimeMillis() + 5 * 60 * 1000));
        extraClaims.forEach(claims::claim);
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims.build());
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    @Replaces(AuthorizationServerResolver.class)
    static class OktaAuthorizationServerResolver implements AuthorizationServerResolver {
        @Override
        public Optional<AuthorizationServer> resolve(String issuer) {
            return Optional.of(AuthorizationServer.OKTA);
        }
    }

    @Requires(property = "spec.name", value = PROVIDER_SPEC_NAME)
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller(ISSUER_PATH)
    static class ProviderController {
        private final HttpHostResolver httpHostResolver;
        volatile RSAKey key;
        volatile String acceptedUserInfoToken;
        volatile Map<String, Object> userInfoClaims = Map.of();

        ProviderController(HttpHostResolver httpHostResolver) {
            this.httpHostResolver = httpHostResolver;
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Get("/.well-known/openid-configuration")
        String configuration(HttpRequest<?> request) {
            String issuer = httpHostResolver.resolve(request) + ISSUER_PATH;
            return "{\"issuer\":\"" + issuer + "\","
                + "\"authorization_endpoint\":\"" + issuer + "/v1/authorize\","
                + "\"token_endpoint\":\"" + issuer + "/v1/token\","
                + "\"userinfo_endpoint\":\"" + issuer + "/v1/userinfo\","
                + "\"jwks_uri\":\"" + issuer + "/keys\","
                + "\"end_session_endpoint\":\"" + issuer + "/v1/logout\","
                + "\"response_types_supported\":[\"code\"],"
                + "\"subject_types_supported\":[\"public\"],"
                + "\"id_token_signing_alg_values_supported\":[\"RS256\"],"
                + "\"scopes_supported\":[\"openid\",\"profile\",\"email\"],"
                + "\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\"]}";
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Get("/keys")
        String keys() {
            return new JWKSet(List.of(key.toPublicJWK())).toString();
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Get("/v1/userinfo")
        HttpResponse<?> userinfo(@Header String authorization) {
            if (acceptedUserInfoToken != null && authorization.equals("Bearer " + acceptedUserInfoToken)) {
                return HttpResponse.ok(userInfoClaims);
            }
            return HttpResponse.unauthorized();
        }
    }
}
