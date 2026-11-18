/*
 * Copyright 2026 original authors
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
package io.micronaut.security.oauth2.endpoint.authorization.response;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.CollectionUtils;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.uri.QueryStringDecoder;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.oauth2.endpoint.token.request.DefaultTokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.request.context.TokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.security.oauth2.mock.MockOpenIdProvider;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The nonce sent in the authorization request must still be available at the callback. If it is not, the login is
 * refused, whether or not the ID token carries a nonce claim.
 */
class OpenIdCallbackNonceTest {
    private static final String SPEC_NAME = "OpenIdCallbackNonceTest";
    private static final String CLIENT_ID = "relying-party";
    private static final String NONCE_COOKIE = "OPENID_NONCE";
    private static final String JWT_COOKIE = "JWT";

    private static MockOpenIdProvider provider;
    private static EmbeddedServer server;
    private static BlockingHttpClient client;
    private static FixedTokenEndpointClient tokenEndpointClient;

    @BeforeAll
    static void start() {
        provider = MockOpenIdProvider.start();
        server = ApplicationContext.run(EmbeddedServer.class, CollectionUtils.mapOf(
            "spec.name", SPEC_NAME,
            "micronaut.security.authentication", "cookie",
            "micronaut.http.client.follow-redirects", false,
            "micronaut.security.token.jwt.signatures.secret.generator.secret", "pleaseChangeThisSecretForANewOne",
            "micronaut.security.oauth2.clients.auth.client-id", CLIENT_ID,
            "micronaut.security.oauth2.clients.auth.client-secret", "not-a-real-secret",
            "micronaut.security.oauth2.clients.auth.openid.issuer", provider.getIssuer()));
        client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();
        tokenEndpointClient = server.getApplicationContext().getBean(FixedTokenEndpointClient.class);
    }

    @AfterAll
    static void stop() {
        server.close();
        provider.close();
    }

    @Test
    void userIsAuthenticatedWhenThePersistedNonceMatchesTheNonceClaim() {
        AuthorizationRedirect redirect = login();
        String nonce = redirect.cookie(NONCE_COOKIE).getValue();
        tokenEndpointClient.idToken = idToken(nonce);

        assertTrue(isAuthenticatedAfterCallback(redirect, redirect.cookies()));
    }

    @Test
    void userIsNotAuthenticatedWhenTheNonceCookieIsMissingAndTheIdTokenHasNoNonceClaim() {
        AuthorizationRedirect redirect = login();
        tokenEndpointClient.idToken = idToken(null);

        assertFalse(isAuthenticatedAfterCallback(redirect, redirect.cookiesWithout(NONCE_COOKIE)));
    }

    @Test
    void userIsNotAuthenticatedWhenTheNonceCookieIsMissingAndTheIdTokenHasTheNonceClaim() {
        AuthorizationRedirect redirect = login();
        tokenEndpointClient.idToken = idToken(redirect.cookie(NONCE_COOKIE).getValue());

        assertFalse(isAuthenticatedAfterCallback(redirect, redirect.cookiesWithout(NONCE_COOKIE)));
    }

    private static AuthorizationRedirect login() {
        HttpResponse<?> response = client.exchange(HttpRequest.GET("/oauth/login/auth"));
        assertEquals(HttpStatus.FOUND, response.status());
        String location = response.getHeaders().get(HttpHeaders.LOCATION);
        assertNotNull(location);
        String state = new QueryStringDecoder(location).parameters().get("state").getFirst();
        AuthorizationRedirect redirect = new AuthorizationRedirect(state, response.getCookies().getAll());
        assertNotNull(redirect.cookie(NONCE_COOKIE), "the authorization request should persist a nonce");
        return redirect;
    }

    private static String idToken(String nonce) {
        return provider.signedJwt(claims -> {
            claims.subject("sherlock").audience(CLIENT_ID);
            if (nonce != null) {
                claims.claim("nonce", nonce);
            }
        });
    }

    private static boolean isAuthenticatedAfterCallback(AuthorizationRedirect redirect, Collection<Cookie> cookies) {
        MutableHttpRequest<?> request = HttpRequest.POST("/oauth/callback/auth", CollectionUtils.mapOf("code", "code", "state", redirect.state()))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED);
        cookies.forEach(request::cookie);
        try {
            return client.exchange(request).getCookies().get(JWT_COOKIE) != null;
        } catch (HttpClientResponseException e) {
            return e.getResponse().getCookies().get(JWT_COOKIE) != null;
        }
    }

    private record AuthorizationRedirect(String state, Collection<Cookie> cookies) {
        Cookie cookie(String name) {
            return cookies.stream().filter(cookie -> cookie.getName().equals(name)).findFirst().orElse(null);
        }

        Collection<Cookie> cookiesWithout(String name) {
            return cookies.stream().filter(cookie -> !cookie.getName().equals(name)).toList();
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Replaces(DefaultTokenEndpointClient.class)
    @Singleton
    static class FixedTokenEndpointClient implements TokenEndpointClient {
        volatile String idToken;

        @Override
        @SuppressWarnings("unchecked")
        public <G, R extends TokenResponse> Publisher<R> sendRequest(TokenRequestContext<G, R> requestContext) {
            OpenIdTokenResponse response = new OpenIdTokenResponse();
            response.setAccessToken("access-token");
            response.setTokenType("bearer");
            response.setIdToken(idToken);
            return Mono.just((R) response);
        }
    }
}
