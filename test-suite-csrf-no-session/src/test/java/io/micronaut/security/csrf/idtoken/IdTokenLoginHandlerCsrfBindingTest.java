package io.micronaut.security.csrf.idtoken;

import io.micronaut.security.oauth2.endpoint.token.response.DefaultOpenIdAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.IdTokenLoginHandler;
import io.micronaut.security.oauth2.endpoint.token.response.JWTOpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;

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
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.server.util.HttpHostResolver;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.config.RedirectService;
import io.micronaut.security.errors.PriorToLoginPersistence;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.cookie.AccessTokenCookieConfiguration;
import io.micronaut.security.token.cookie.LoginCookieProvider;
import jakarta.inject.Singleton;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.serde.annotation.Serdeable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * With {@code micronaut.security.authentication=idtoken} and two enabled OpenID clients, {@link DefaultOpenIdAuthenticationMapper}
 * names the user {@code <provider>:<sub>} at login, while later requests are authenticated with the ID token and named by its
 * {@code sub} claim. The signed CSRF cookie issued at login must be bound to the latter, so that it is accepted afterwards,
 * and must still be rejected for another user.
 */
class IdTokenLoginHandlerCsrfBindingTest {
    private static final String SPEC_NAME = "IdTokenLoginHandlerCsrfBindingTest";
    private static final String PROVIDER_SPEC_NAME = "IdTokenLoginHandlerCsrfBindingTestProvider";
    private static final String ISSUER_PATH = "/oauth2/default";
    private static final String CLIENT_ID = "relying-party";
    private static final String CSRF_COOKIE_NAME = "__Host-csrfToken";
    private static final RSAKey PROVIDER_KEY = generateKey("csrf-binding-test-provider-key");

    private static EmbeddedServer provider;

    @BeforeAll
    static void startProvider() {
        provider = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", PROVIDER_SPEC_NAME));
    }

    @AfterAll
    static void stopProvider() {
        if (provider != null) {
            provider.close();
        }
    }

    @Test
    void csrfCookieIssuedAtLoginIsAcceptedOnLaterRequestsAuthenticatedWithTheIdToken() {
        try (EmbeddedServer server = startRelyingParty(Map.of());
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            DefaultOpenIdAuthenticationMapper mapper = server.getApplicationContext().getBean(DefaultOpenIdAuthenticationMapper.class);
            assertTrue(mapper.isQualifyUsernameWithProvider(), "two enabled clients qualify the username with the provider name");
            IdTokenLoginHandler loginHandler = server.getApplicationContext().getBean(IdTokenLoginHandler.class);

            LoginCookies sherlock = login(mapper, loginHandler, "sherlock");
            LoginCookies moriarty = login(mapper, loginHandler, "moriarty");
            assertEquals("auth:sherlock", sherlock.loginName(), "the mapper qualifies the name at login");

            // accepted: later requests are named by the ID token sub, and the CSRF cookie issued at login is bound to it
            assertEquals("sherlock", assertOk(client, sherlock.idToken(), sherlock.csrfToken()));
            assertEquals("moriarty", assertOk(client, moriarty.idToken(), moriarty.csrfToken()));

            // rejected: another user's correctly signed token planted in the cookie
            assertDenied(client, sherlock.idToken(), moriarty.csrfToken());
            assertDenied(client, moriarty.idToken(), sherlock.csrfToken());
        }
    }

    @Test
    void legacySubclassBindsTheCsrfCookieToTheConfiguredNameKeyClaim() {
        try (EmbeddedServer server = startRelyingParty(Map.of("micronaut.security.token.name-key", "email"));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            DefaultOpenIdAuthenticationMapper mapper = server.getApplicationContext().getBean(DefaultOpenIdAuthenticationMapper.class);
            IdTokenLoginHandler loginHandler = server.getApplicationContext().getBean(IdTokenLoginHandler.class);
            assertTrue(loginHandler instanceof LegacyIdTokenLoginHandler, "the handler is a subclass using the pre-existing constructor");

            LoginCookies sherlock = login(mapper, loginHandler, "sherlock");
            LoginCookies moriarty = login(mapper, loginHandler, "moriarty");
            assertEquals("auth:sherlock", sherlock.loginName());

            // accepted: later requests are named by the ID token email claim, and the CSRF cookie issued at login is bound to it
            assertEquals("sherlock@example.com", assertOk(client, sherlock.idToken(), sherlock.csrfToken()));
            assertEquals("moriarty@example.com", assertOk(client, moriarty.idToken(), moriarty.csrfToken()));
            assertDenied(client, sherlock.idToken(), moriarty.csrfToken());
        }
    }

    private static LoginCookies login(DefaultOpenIdAuthenticationMapper mapper, IdTokenLoginHandler loginHandler, String subject) {
        JWTClaimsSet claims = claims(subject);
        OpenIdTokenResponse tokenResponse = new OpenIdTokenResponse();
        tokenResponse.setAccessToken("access-token-" + subject);
        tokenResponse.setTokenType("Bearer");
        tokenResponse.setIdToken(signedIdToken(claims));
        AuthenticationResponse authenticationResponse = Mono.from(mapper.createAuthenticationResponse("auth", tokenResponse, new JWTOpenIdClaims(claims), null)).block();
        assertNotNull(authenticationResponse);
        Authentication authentication = authenticationResponse.getAuthentication().orElseThrow();

        MutableHttpResponse<?> loginResponse = loginHandler.loginSuccess(authentication, HttpRequest.GET("/oauth/callback/auth"));
        Optional<Cookie> idTokenCookie = loginResponse.getCookie("JWT");
        assertTrue(idTokenCookie.isPresent());
        Optional<Cookie> csrfCookie = loginResponse.getCookie(CSRF_COOKIE_NAME);
        assertTrue(csrfCookie.isPresent());
        return new LoginCookies(authentication.getName(), idTokenCookie.get().getValue(), csrfCookie.get().getValue());
    }

    private static String assertOk(BlockingHttpClient client, String idToken, String csrfToken) {
        HttpResponse<String> response = assertDoesNotThrow(() -> client.exchange(passwordChange(idToken, csrfToken), String.class));
        assertEquals(HttpStatus.OK, response.getStatus());
        return response.body();
    }

    private static void assertDenied(BlockingHttpClient client, String idToken, String csrfToken) {
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(passwordChange(idToken, csrfToken)));
        assertEquals(HttpStatus.FORBIDDEN, ex.getStatus());
    }

    private static HttpRequest<?> passwordChange(String idToken, String csrfToken) {
        return HttpRequest.POST("/password/change", new PasswordChangeForm("evil", csrfToken))
                .cookie(Cookie.of("JWT", idToken))
                .cookie(Cookie.of(CSRF_COOKIE_NAME, csrfToken))
                .accept(MediaType.TEXT_PLAIN)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
    }

    private static EmbeddedServer startRelyingParty(Map<String, Object> extra) {
        Map<String, Object> configuration = new HashMap<>(extra);
        configuration.put("spec.name", SPEC_NAME);
        configuration.put("micronaut.security.authentication", "idtoken");
        configuration.put("micronaut.security.redirect.enabled", StringUtils.FALSE);
        configuration.put("micronaut.security.csrf.signature-key", "test-fixture-not-a-secret-csrf-signature-key");
        for (String name : List.of("auth", "other")) {
            configuration.put("micronaut.security.oauth2.clients." + name + ".client-id", CLIENT_ID);
            configuration.put("micronaut.security.oauth2.clients." + name + ".client-secret", "test-fixture-not-a-secret");
            configuration.put("micronaut.security.oauth2.clients." + name + ".openid.issuer", issuer());
        }
        return ApplicationContext.run(EmbeddedServer.class, configuration);
    }

    private static String issuer() {
        return provider.getURL() + ISSUER_PATH;
    }

    private static JWTClaimsSet claims(String subject) {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
            .issuer(issuer())
            .subject(subject)
            .claim("email", subject + "@example.com")
            .audience(CLIENT_ID)
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(3600)))
            .build();
    }

    private static String signedIdToken(JWTClaimsSet claims) {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(PROVIDER_KEY.getKeyID()).build(), claims);
        try {
            jwt.sign(new RSASSASigner(PROVIDER_KEY));
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
        return jwt.serialize();
    }

    private static RSAKey generateKey(String keyId) {
        try {
            return new RSAKeyGenerator(2048).keyID(keyId).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    record LoginCookies(String loginName, String idToken, String csrfToken) {
    }

    @Serdeable
    record PasswordChangeForm(String password, String csrfToken) {
    }

    /**
     * A subclass written before 4.18.2 using the pre-existing constructor.
     */
    @Requires(property = "spec.name", value = SPEC_NAME)
    @Replaces(IdTokenLoginHandler.class)
    @Singleton
    static class LegacyIdTokenLoginHandler extends IdTokenLoginHandler {
        LegacyIdTokenLoginHandler(AccessTokenCookieConfiguration accessTokenCookieConfiguration,
                                  RedirectConfiguration redirectConfiguration,
                                  RedirectService redirectService,
                                  @Nullable PriorToLoginPersistence<HttpRequest<?>, MutableHttpResponse<?>> priorToLoginPersistence,
                                  List<LoginCookieProvider<HttpRequest<?>>> loginCookieProviders) {
            super(accessTokenCookieConfiguration, redirectConfiguration, redirectService, priorToLoginPersistence, loginCookieProviders);
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller
    @Produces(MediaType.TEXT_PLAIN)
    static class PasswordChangeController {
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post("/password/change")
        String changePassword(@Body PasswordChangeForm form, Authentication authentication) {
            return authentication.getName();
        }
    }

    @Requires(property = "spec.name", value = PROVIDER_SPEC_NAME)
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller(ISSUER_PATH)
    static class ProviderController {
        private final HttpHostResolver httpHostResolver;

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
                + "\"response_types_supported\":[\"code\",\"id_token\",\"code id_token\"],"
                + "\"subject_types_supported\":[\"public\"],"
                + "\"id_token_signing_alg_values_supported\":[\"RS256\"],"
                + "\"scopes_supported\":[\"openid\",\"profile\",\"email\"],"
                + "\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\"],"
                + "\"code_challenge_methods_supported\":[\"S256\"]}";
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Get("/keys")
        String keys() {
            return new JWKSet(PROVIDER_KEY.toPublicJWK()).toString();
        }
    }
}
