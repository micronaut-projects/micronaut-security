/*
 * Copyright 2017-2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.fetchmetadata;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Error;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.server.util.HttpHostResolver;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.fetchmetadata.rules.FetchMetadataRulesConfiguration;
import io.micronaut.security.oauth2.client.OauthClient;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.security.oauth2.routes.DefaultOauthController;
import io.micronaut.security.oauth2.routes.OauthController;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * With Micronaut Security Fetch Metadata installed, another site cannot send the browser to the OAuth 2.0 login
 * route and log the user in without their intent.
 */
class OauthLoginFetchMetadataTest {

    private static final String SPEC_NAME = "OauthLoginFetchMetadataTest";
    private static final String PROVIDER_SPEC_NAME = SPEC_NAME + "Provider";
    private static final String OIDC_PATH = "/oidc";

    private static EmbeddedServer provider;
    private static EmbeddedServer app;
    private static EmbeddedServer customLoginUriApp;
    private static EmbeddedServer protectionDisabledApp;
    private static EmbeddedServer customControllerApp;

    @BeforeAll
    static void startServers() {
        provider = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", PROVIDER_SPEC_NAME));
        app = ApplicationContext.run(EmbeddedServer.class, configuration(SPEC_NAME, Map.of()));
        customLoginUriApp = ApplicationContext.run(EmbeddedServer.class, configuration(SPEC_NAME,
            Map.of("micronaut.security.oauth2.login-uri", "/sign-in{/provider}")));
        protectionDisabledApp = ApplicationContext.run(EmbeddedServer.class, configuration(SPEC_NAME,
            Map.of(FetchMetadataRulesConfiguration.PROPERTY_ALLOW_CROSS_SITE_NAVIGATION_TO_ANNOTATED_ROUTES, StringUtils.TRUE)));
        customControllerApp = ApplicationContext.run(EmbeddedServer.class, configuration(SPEC_NAME + "CustomController",
            Map.of()));
    }

    @AfterAll
    static void stopServers() {
        for (EmbeddedServer server : new EmbeddedServer[] {app, customLoginUriApp, protectionDisabledApp, customControllerApp, provider}) {
            if (server != null) {
                server.close();
            }
        }
    }

    @Test
    void annotationNameMatchesTheNameTheOauthModuleTestsCheck() {
        // security-oauth2 depends on the annotation compileOnly and its tests check it by this name
        // (OauthLoginRouteDenyCrossSiteNavigationTest): renaming or moving the annotation must fail here
        assertEquals("io.micronaut.security.fetchmetadata.DenyCrossSiteNavigation", DenyCrossSiteNavigation.class.getName());
    }

    @Test
    void crossSiteNavigationToTheLoginRouteIsRejected() {
        assertRejected(app, navigation("/oauth/login/auth", "cross-site"));
    }

    @Test
    void unauthorizedRedirectToTheLoginRouteIsRejectedForUsersArrivingFromAnotherSite() {
        try (EmbeddedServer redirecting = ApplicationContext.run(EmbeddedServer.class, configuration(SPEC_NAME + "UnauthorizedRedirect",
            Map.of("micronaut.security.redirect.unauthorized.url", "/oauth/login/auth")))) {
            // a link from another site to a secured page is a cross-site navigation, which the filter allows
            HttpResponse<?> secured = exchange(redirecting, navigation("/secured", "cross-site").accept(MediaType.TEXT_HTML));
            assertEquals(HttpStatus.SEE_OTHER, secured.status());
            assertEquals("/oauth/login/auth", secured.getHeaders().get(HttpHeaders.LOCATION));

            // the browser reports the redirected navigation as cross-site, so the login route refuses it
            assertRejected(redirecting, navigation("/oauth/login/auth", "cross-site"));
        }
    }

    @Test
    void errorRouteForForbiddenDoesNotRenderTheRejection() {
        HttpResponse<?> response = exchange(app, navigation("/oauth/login/auth", "cross-site"));

        assertEquals(HttpStatus.FORBIDDEN, response.status());
        assertTrue(response.getBody(String.class).isEmpty(), () -> response.getBody(String.class).orElse(""));
    }

    @Test
    void filterPatternForTheLoginRoutesMustNotIncludeTheContextPath() {
        Map<String, Object> withoutContextPath = Map.of("micronaut.server.context-path", "/app",
            FetchMetadataFilterConfiguration.PROPERTY_PATTERN, "/oauth/login/**");
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, configuration(SPEC_NAME, withoutContextPath))) {
            assertRejected(server, navigation("/oauth/login/auth", "cross-site"));
        }
        Map<String, Object> withContextPath = Map.of("micronaut.server.context-path", "/app",
            FetchMetadataFilterConfiguration.PROPERTY_PATTERN, "/app/oauth/login/**");
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, configuration(SPEC_NAME, withContextPath))) {
            // documented limit: a pattern that includes the context path does not cover the login route
            assertEquals(HttpStatus.FOUND, exchange(server, navigation("/oauth/login/auth", "cross-site")).status());
        }
    }

    @Test
    void filterPatternLimitedToTheLoginRoutesStillCoversEveryLoginRoute() {
        try (EmbeddedServer loginOnly = ApplicationContext.run(EmbeddedServer.class, configuration(SPEC_NAME,
            Map.of(FetchMetadataFilterConfiguration.PROPERTY_PATTERN, "/oauth/login/**")))) {
            assertRejected(loginOnly, navigation("/oauth/login/auth", "cross-site"));
            assertRejected(loginOnly, navigation("/oauth/login", "cross-site"));
            assertRejected(loginOnly, navigation("/oauth/login/oidc", "cross-site"));
            // outside the pattern, a cross-site form_post callback is not evaluated by the filter
            HttpResponse<?> callback = exchange(loginOnly, HttpRequest.POST("/oauth/callback/auth", "code=code-fixture&state=state-fixture")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.SEC_FETCH_SITE, "cross-site")
                .header(HttpHeaders.SEC_FETCH_MODE, "navigate")
                .header(HttpHeaders.SEC_FETCH_DEST, "document"));
            assertNotEquals(HttpStatus.FORBIDDEN, callback.status());
        }
    }

    @Test
    void crossSiteNavigationToTheDefaultProviderLoginRouteIsRejected() {
        assertRejected(app, navigation("/oauth/login", "cross-site"));
    }

    @Test
    void crossSiteNavigationToTheOpenIdLoginRouteIsRejected() {
        assertRejected(app, navigation("/oauth/login/oidc", "cross-site"));
    }

    @Test
    void crossSiteNavigationToALoginRouteAtACustomUriIsRejected() {
        assertRejected(customLoginUriApp, navigation("/sign-in/auth", "cross-site"));
        assertRedirectsToTheProvider(customLoginUriApp, navigation("/sign-in/auth", "same-origin"), "/authorize");
    }

    @Test
    void crossSiteNavigationToTheLoginRouteOfACustomControllerIsRejected() {
        assertRejected(customControllerApp, navigation("/oauth/login/auth", "cross-site"));

        HttpResponse<?> response = exchange(customControllerApp, navigation("/oauth/login/auth", "same-origin"));
        assertEquals(HttpStatus.FOUND, response.status());
        assertTrue(response.getHeaders().get(HttpHeaders.LOCATION).startsWith(provider.getURL() + "/authorize?"));
        // no-store comes from DefaultOauthController, which the application's controller replaces
        assertNull(response.getHeaders().get(HttpHeaders.CACHE_CONTROL));
    }

    @Test
    void sameSiteNavigationToTheLoginRouteIsRejected() {
        assertRejected(app, navigation("/oauth/login/auth", "same-site"));
    }

    @Test
    void sameOriginNavigationToTheLoginRouteRedirectsToTheProvider() {
        assertRedirectsToTheProvider(app, navigation("/oauth/login/auth", "same-origin"), "/authorize");
    }

    @Test
    void sameOriginNavigationToTheDefaultProviderLoginRouteRedirectsToTheProvider() {
        assertRedirectsToTheProvider(app, navigation("/oauth/login", "same-origin"), "/authorize");
    }

    @Test
    void sameOriginNavigationToTheOpenIdLoginRouteRedirectsToTheProvider() {
        assertRedirectsToTheProvider(app, navigation("/oauth/login/oidc", "same-origin"), OIDC_PATH + "/authorize");
    }

    @Test
    void addressBarNavigationAndRequestsWithoutFetchMetadataReachTheLoginRoute() {
        assertRedirectsToTheProvider(app, navigation("/oauth/login/auth", "none"), "/authorize");
        assertRedirectsToTheProvider(app, HttpRequest.GET("/oauth/login/auth"), "/authorize");
    }

    @Test
    void crossSiteNavigationToTheLoginRouteIsAllowedWhenTheProtectionIsDisabled() {
        assertRedirectsToTheProvider(protectionDisabledApp, navigation("/oauth/login/auth", "cross-site"), "/authorize");
    }

    @Test
    void crossSiteNavigationFromTheProviderStillReachesTheCallbackRoute() {
        HttpResponse<?> login = exchange(app, navigation("/oauth/login/auth", "same-origin"));
        String state = queryParameter(login.getHeaders().get(HttpHeaders.LOCATION), "state");
        Cookie stateCookie = login.getCookies().get("OAUTH2_STATE");
        assertNotNull(stateCookie);

        HttpResponse<?> response = exchange(app, navigation("/oauth/callback/auth?code=code-fixture&state="
            + URLEncoder.encode(state, StandardCharsets.UTF_8), "cross-site").cookie(stateCookie));

        assertEquals(HttpStatus.SEE_OTHER, response.status());
        assertEquals("/", response.getHeaders().get(HttpHeaders.LOCATION));
        assertNotNull(response.getCookies().get("JWT"));
    }

    private static void assertRejected(EmbeddedServer server, HttpRequest<?> request) {
        HttpResponse<?> response = exchange(server, request);

        assertEquals(HttpStatus.FORBIDDEN, response.status());
        assertNull(response.getHeaders().get(HttpHeaders.LOCATION));
        assertTrue(response.getHeaders().getAll(HttpHeaders.SET_COOKIE).isEmpty(),
            "no state, PKCE or nonce cookie must be issued");
    }

    private static void assertRedirectsToTheProvider(EmbeddedServer server, HttpRequest<?> request, String authorizationPath) {
        HttpResponse<?> response = exchange(server, request);

        assertEquals(HttpStatus.FOUND, response.status());
        String location = response.getHeaders().get(HttpHeaders.LOCATION);
        assertNotNull(location);
        assertTrue(location.startsWith(provider.getURL() + authorizationPath + "?"), location);
        assertEquals("no-store", response.getHeaders().get(HttpHeaders.CACHE_CONTROL));
        List<String> cookies = response.getHeaders().getAll(HttpHeaders.SET_COOKIE);
        assertTrue(cookies.stream().anyMatch(cookie -> cookie.startsWith("OAUTH2_STATE=")), cookies::toString);
    }

    private static HttpResponse<?> exchange(EmbeddedServer server, HttpRequest<?> request) {
        try (HttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            return client.toBlocking().exchange(request);
        } catch (HttpClientResponseException e) {
            return e.getResponse();
        }
    }

    private static String queryParameter(String uri, String name) {
        for (String parameter : URI.create(uri).getRawQuery().split("&")) {
            if (parameter.startsWith(name + "=")) {
                return URLDecoder.decode(parameter.substring(name.length() + 1), StandardCharsets.UTF_8);
            }
        }
        throw new AssertionError("no " + name + " in " + uri);
    }

    private static MutableHttpRequest<?> navigation(String path, String site) {
        return HttpRequest.GET(path)
            .header(HttpHeaders.SEC_FETCH_SITE, site)
            .header(HttpHeaders.SEC_FETCH_MODE, "navigate")
            .header(HttpHeaders.SEC_FETCH_DEST, "document");
    }

    private static Map<String, Object> configuration(String specName, Map<String, Object> overrides) {
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("spec.name", specName);
        configuration.put("micronaut.security.authentication", "cookie");
        configuration.put("micronaut.http.client.follow-redirects", false);
        configuration.put("micronaut.security.token.jwt.signatures.secret.generator.secret", "test-fixture-not-a-secret-test-fixture-not-a-secret");
        configuration.put("micronaut.security.oauth2.default-provider", "auth");
        configuration.put("micronaut.security.oauth2.clients.auth.authorization.url", provider.getURL() + "/authorize");
        configuration.put("micronaut.security.oauth2.clients.auth.token.url", provider.getURL() + "/token");
        configuration.put("micronaut.security.oauth2.clients.auth.client-id", "client-id-fixture");
        configuration.put("micronaut.security.oauth2.clients.auth.client-secret", "client-secret-fixture-not-a-secret");
        configuration.put("micronaut.security.oauth2.clients.oidc.openid.issuer", provider.getURL() + OIDC_PATH);
        configuration.put("micronaut.security.oauth2.clients.oidc.client-id", "client-id-fixture");
        configuration.put("micronaut.security.oauth2.clients.oidc.client-secret", "client-secret-fixture-not-a-secret");
        configuration.putAll(overrides);
        return configuration;
    }

    @Requires(property = "spec.name", pattern = SPEC_NAME + "(CustomController|UnauthorizedRedirect)?")
    @Singleton
    @Named("auth")
    static class AuthenticationMapper implements OauthAuthenticationMapper {
        @Override
        public Publisher<AuthenticationResponse> createAuthenticationResponse(TokenResponse tokenResponse, @Nullable State state) {
            return Mono.just(AuthenticationResponse.success("user"));
        }
    }

    /**
     * An application's own controller, which does not repeat the annotation of {@link OauthController#login}.
     */
    @Requires(property = "spec.name", value = SPEC_NAME + "CustomController")
    @Replaces(DefaultOauthController.class)
    @EachBean(OauthClient.class)
    static class CustomOauthController implements OauthController {
        private final OauthClient client;

        CustomOauthController(@Parameter OauthClient client) {
            this.client = client;
        }

        @Override
        public OauthClient getClient() {
            return client;
        }

        @Override
        public Publisher<MutableHttpResponse<?>> login(HttpRequest<?> request) {
            return client.authorizationRedirect(request);
        }

        @Override
        public Publisher<MutableHttpResponse<?>> callback(HttpRequest<Map<String, Object>> request) {
            return Mono.just(HttpResponse.ok());
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME + "UnauthorizedRedirect")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller("/secured")
    static class SecuredController {
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String secured() {
            return "secured";
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller
    static class ForbiddenErrorController {
        @Produces(MediaType.TEXT_PLAIN)
        @Error(status = HttpStatus.FORBIDDEN, global = true)
        String forbidden() {
            return "friendly forbidden page";
        }
    }

    @Requires(property = "spec.name", value = PROVIDER_SPEC_NAME)
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller
    static class OauthProviderController {
        @Produces(MediaType.APPLICATION_JSON)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post("/token")
        String token() {
            return "{\"access_token\":\"access-token-fixture\",\"token_type\":\"bearer\",\"expires_in\":3600}";
        }
    }

    @Requires(property = "spec.name", value = PROVIDER_SPEC_NAME)
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller(OIDC_PATH)
    static class OpenIdProviderController {
        private final HttpHostResolver httpHostResolver;

        OpenIdProviderController(HttpHostResolver httpHostResolver) {
            this.httpHostResolver = httpHostResolver;
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Get("/.well-known/openid-configuration")
        String configuration(HttpRequest<?> request) {
            String issuer = httpHostResolver.resolve(request) + OIDC_PATH;
            return "{\"issuer\":\"" + issuer + "\","
                + "\"authorization_endpoint\":\"" + issuer + "/authorize\","
                + "\"token_endpoint\":\"" + issuer + "/token\","
                + "\"jwks_uri\":\"" + issuer + "/keys\","
                + "\"response_types_supported\":[\"code\"],"
                + "\"subject_types_supported\":[\"public\"],"
                + "\"id_token_signing_alg_values_supported\":[\"RS256\"],"
                + "\"scopes_supported\":[\"openid\"],"
                + "\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\"],"
                + "\"code_challenge_methods_supported\":[\"S256\"]}";
        }
    }
}
