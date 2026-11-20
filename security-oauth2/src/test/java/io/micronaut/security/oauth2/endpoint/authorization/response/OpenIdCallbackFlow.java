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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
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
import io.micronaut.security.oauth2.endpoint.token.response.validation.NonceClaimValidator;
import io.micronaut.security.oauth2.mock.MockOpenIdProvider;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * An application with an OpenID client named {@code auth}, a mock OpenID provider and a token endpoint which returns
 * the ID token the test chooses. Drives the login redirect and the callback of the authorization code flow.
 */
final class OpenIdCallbackFlow implements AutoCloseable {
    private static final String SPEC_NAME = "OpenIdCallbackFlow";
    private static final String CLIENT_ID = "relying-party";
    private static final String JWT_COOKIE = "JWT";

    private final MockOpenIdProvider provider;
    private final EmbeddedServer server;
    private final BlockingHttpClient client;
    private final FixedTokenEndpointClient tokenEndpointClient;

    private OpenIdCallbackFlow(Map<String, Object> additionalConfiguration) {
        provider = MockOpenIdProvider.start();
        Map<String, Object> configuration = new HashMap<>(CollectionUtils.mapOf(
            "spec.name", SPEC_NAME,
            "micronaut.security.authentication", "cookie",
            "micronaut.http.client.follow-redirects", false,
            "micronaut.security.token.jwt.signatures.secret.generator.secret", "pleaseChangeThisSecretForANewOne",
            "micronaut.security.oauth2.clients.auth.client-id", CLIENT_ID,
            "micronaut.security.oauth2.clients.auth.client-secret", "not-a-real-secret",
            "micronaut.security.oauth2.clients.auth.openid.issuer", provider.getIssuer()));
        configuration.putAll(additionalConfiguration);
        server = ApplicationContext.run(EmbeddedServer.class, configuration);
        client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();
        tokenEndpointClient = server.getApplicationContext().getBean(FixedTokenEndpointClient.class);
    }

    /**
     * @param additionalConfiguration Configuration added to the application
     * @return A started application and OpenID provider
     */
    static OpenIdCallbackFlow start(Map<String, Object> additionalConfiguration) {
        return new OpenIdCallbackFlow(additionalConfiguration);
    }

    /**
     * @return The state and nonce the application sent in the authorization request, and the cookies it set
     */
    AuthorizationRedirect login() {
        HttpResponse<?> response = client.exchange(HttpRequest.GET("/oauth/login/auth"));
        assertEquals(HttpStatus.FOUND, response.status());
        String location = response.getHeaders().get(HttpHeaders.LOCATION);
        assertNotNull(location);
        Map<String, List<String>> parameters = new QueryStringDecoder(location).parameters();
        assertNotNull(parameters.get("nonce"), "the authorization request should carry a nonce");
        return new AuthorizationRedirect(parameters.get("state").getFirst(), parameters.get("nonce").getFirst(), response.getCookies().getAll());
    }

    /**
     * @param nonce The nonce claim of the ID token the token endpoint will return, or {@code null} for no nonce claim
     */
    void tokenEndpointReturnsIdTokenWithNonce(String nonce) {
        tokenEndpointClient.idToken = provider.signedJwt(claims -> {
            claims.subject("sherlock").audience(CLIENT_ID);
            if (nonce != null) {
                claims.claim("nonce", nonce);
            }
        });
    }

    /**
     * @param redirect The authorization redirect the callback answers
     * @param cookies The cookies the browser sends to the callback
     * @return Whether the callback logged the user in
     */
    boolean isAuthenticatedAfterCallback(AuthorizationRedirect redirect, Collection<Cookie> cookies) {
        return callback(redirect, cookies).authenticated();
    }

    /**
     * @param redirect The authorization redirect the callback answers
     * @param cookies The cookies the browser sends to the callback
     * @return Whether the callback logged the user in, and whether the nonce validation found no persisted nonce
     */
    CallbackOutcome callback(AuthorizationRedirect redirect, Collection<Cookie> cookies) {
        MutableHttpRequest<?> request = HttpRequest.POST("/oauth/callback/auth", CollectionUtils.mapOf("code", "code", "state", redirect.state()))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED);
        cookies.forEach(request::cookie);
        Logger logger = (Logger) LoggerFactory.getLogger(NonceClaimValidator.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            HttpResponse<?> response;
            try {
                response = client.exchange(request);
            } catch (HttpClientResponseException e) {
                response = e.getResponse();
            }
            boolean persistedNonceMissing = appender.list.stream().anyMatch(event -> event.getLevel() == Level.WARN);
            return new CallbackOutcome(response.getCookies().get(JWT_COOKIE) != null, persistedNonceMissing);
        } finally {
            logger.detachAppender(appender);
        }
    }

    @Override
    public void close() {
        server.close();
        provider.close();
    }

    /**
     * @param authenticated Whether the callback logged the user in
     * @param persistedNonceMissing Whether the nonce validation reported that no persisted nonce could be retrieved
     */
    record CallbackOutcome(boolean authenticated, boolean persistedNonceMissing) {
    }

    record AuthorizationRedirect(String state, String nonce, Collection<Cookie> cookies) {
        boolean hasCookie(String name) {
            return cookies.stream().anyMatch(cookie -> cookie.getName().equals(name));
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
