package io.micronaut.security.oauth2.endpoint.authorization.response;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.CollectionUtils;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
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
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.security.oauth2.grants.AuthorizationCodeGrant;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import io.micronaut.core.annotation.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * The redirect_uri the plain OAuth 2.0 client sends to the token endpoint must be the application's own
 * callback URL, never a value taken from the attacker controllable state parameter.
 */
class OauthCallbackRedirectUriTest {

    private static final String ATTACKER_REDIRECT_URI = "https://attacker.example/evil";
    private static final String STOLEN_CODE = "stolen-code-fixture";
    private static final String STATE_COOKIE = "OAUTH2_STATE";
    private static final String JWT_COOKIE = "JWT";

    private static EmbeddedServer authServer;
    private static EmbeddedServer server;
    private static BlockingHttpClient client;
    private static BlockingHttpClient authServerClient;
    private static AuthServerController authServerController;

    @BeforeAll
    static void startServers() {
        authServer = ApplicationContext.run(EmbeddedServer.class, Map.of(
            "spec.name", "OauthCallbackRedirectUriTestAuthServer"));
        server = ApplicationContext.run(EmbeddedServer.class, CollectionUtils.mapOf(
            "spec.name", "OauthCallbackRedirectUriTest",
            "micronaut.security.authentication", "cookie",
            "micronaut.http.client.follow-redirects", false,
            "micronaut.security.token.jwt.signatures.secret.generator.secret", "test-fixture-not-a-secret-test-fixture-not-a-secret",
            "micronaut.security.oauth2.clients.auth.authorization.url", authServer.getURL() + "/authorize",
            "micronaut.security.oauth2.clients.auth.token.url", authServer.getURL() + "/token",
            "micronaut.security.oauth2.clients.auth.client-id", "client-id-fixture",
            "micronaut.security.oauth2.clients.auth.client-secret", "client-secret-fixture-not-a-secret"));
        client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();
        authServerClient = authServer.getApplicationContext().createBean(HttpClient.class, authServer.getURL()).toBlocking();
        authServerController = authServer.getApplicationContext().getBean(AuthServerController.class);
    }

    @AfterAll
    static void stopServers() {
        if (server != null) {
            server.close();
        }
        if (authServer != null) {
            authServer.close();
        }
    }

    @BeforeEach
    void reset() {
        authServerController.reset();
    }

    private static String callbackUrl() {
        return server.getURL() + "/oauth/callback/auth";
    }

    @Test
    void legitimateFlowSendsTheApplicationCallbackUrlAsRedirectUri() {
        HttpResponse<?> response = client.exchange(HttpRequest.GET("/oauth/login/auth"));
        assertEquals(HttpStatus.FOUND, response.status());
        String location = response.getHeaders().get(HttpHeaders.LOCATION);
        assertNotNull(location);
        Cookie stateCookie = response.getCookies().get(STATE_COOKIE);
        assertNotNull(stateCookie);

        authServerClient.exchange(HttpRequest.GET(location));
        assertEquals(callbackUrl(), authServerController.authorizationRedirectUri);
        assertNotNull(authServerController.lastState);
        assertNotNull(authServerController.lastCode);

        response = client.exchange(callback(authServerController.lastCode, authServerController.lastState, stateCookie));

        assertEquals(HttpStatus.SEE_OTHER, response.status());
        assertEquals("/", response.getHeaders().get(HttpHeaders.LOCATION));
        assertNotNull(response.getCookies().get(JWT_COOKIE));
        assertEquals(callbackUrl(), authServerController.tokenRedirectUri);
    }

    @Test
    void stolenCodeCannotBeRedeemedWithRedirectUriChosenByTheAttacker() {
        // the provider issued this code for a redirect_uri which is not the application callback
        authServerController.codes.put(STOLEN_CODE, ATTACKER_REDIRECT_URI);

        String json = "{\"nonce\":\"" + UUID.randomUUID() + "\",\"redirectUri\":\"" + ATTACKER_REDIRECT_URI + "\"}";
        String forgedState = Base64.getUrlEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));
        Cookie forgedStateCookie = Cookie.of(STATE_COOKIE, forgedState);

        HttpStatus status;
        boolean jwtCookie;
        try {
            HttpResponse<?> response = client.exchange(callback(STOLEN_CODE, forgedState, forgedStateCookie));
            status = response.status();
            jwtCookie = response.getCookies().get(JWT_COOKIE) != null;
        } catch (HttpClientResponseException e) {
            status = e.getStatus();
            jwtCookie = e.getResponse().getCookies().get(JWT_COOKIE) != null;
        }

        assertNotNull(authServerController.tokenRedirectUri, "the token endpoint should have been called");
        assertNotEquals(ATTACKER_REDIRECT_URI, authServerController.tokenRedirectUri,
            "the redirect_uri sent to the token endpoint must not be taken from the state parameter");
        assertEquals(callbackUrl(), authServerController.tokenRedirectUri);
        assertFalse(jwtCookie, "the attacker must not be logged in, status was " + status);
    }

    private static HttpRequest<?> callback(String code, String state, Cookie stateCookie) {
        return HttpRequest.POST("/oauth/callback/auth", CollectionUtils.mapOf("code", code, "state", state))
            .cookie(stateCookie)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED);
    }

    @Requires(property = "spec.name", value = "OauthCallbackRedirectUriTest")
    @Singleton
    @Named("auth")
    static class MockOauthAuthenticationMapper implements OauthAuthenticationMapper {
        @Override
        public Publisher<AuthenticationResponse> createAuthenticationResponse(TokenResponse tokenResponse, @Nullable State state) {
            return Mono.just(AuthenticationResponse.success("victim"));
        }
    }

    @Requires(property = "spec.name", value = "OauthCallbackRedirectUriTestAuthServer")
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller
    static class AuthServerController {
        final Map<String, String> codes = new ConcurrentHashMap<>();
        volatile String lastState;
        volatile String lastCode;
        volatile String authorizationRedirectUri;
        volatile String tokenRedirectUri;

        void reset() {
            codes.clear();
            lastState = null;
            lastCode = null;
            authorizationRedirectUri = null;
            tokenRedirectUri = null;
        }

        @Produces(MediaType.TEXT_HTML)
        @Get("/authorize")
        String authorize(HttpRequest<?> request) {
            lastState = request.getParameters().get("state");
            authorizationRedirectUri = request.getParameters().get("redirect_uri");
            lastCode = "code-" + UUID.randomUUID();
            codes.put(lastCode, authorizationRedirectUri);
            return "ok";
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post("/token")
        HttpResponse<?> token(@Body AuthorizationCodeGrant codeGrant) {
            tokenRedirectUri = codeGrant.getRedirectUri();
            String boundRedirectUri = codeGrant.getCode() == null ? null : codes.get(codeGrant.getCode());
            // RFC 6749 section 4.1.3: redirect_uri must match the one used in the authorization request
            if (boundRedirectUri == null || tokenRedirectUri == null || !boundRedirectUri.equals(tokenRedirectUri)) {
                return HttpResponse.badRequest(Map.of("error", "invalid_grant"));
            }
            TokenResponse tokenResponse = new TokenResponse();
            tokenResponse.setAccessToken("access-token-fixture-not-a-secret");
            tokenResponse.setTokenType("Bearer");
            return HttpResponse.ok(tokenResponse);
        }
    }
}
