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
package io.micronaut.security.oauth2.client;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.oauth2.mock.MockOpenIdProvider;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.jwt.signature.ReactiveSignatureConfiguration;
import io.micronaut.core.annotation.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tokens signed by an OpenID provider's keys, such as ID tokens issued to other clients, must only authenticate requests
 * in {@code idtoken} authentication mode, and there only when they were issued to this client.
 */
class OpenIdProviderTokensAsRequestCredentialsTest {
    private static final String SPEC_NAME = "OpenIdProviderTokensAsRequestCredentialsTest";
    private static final String CLIENT_ID = "relying-party";
    private static final String OTHER_CLIENT_ID = "other-client";

    @ParameterizedTest(name = "authentication mode {0}")
    @NullSource
    @ValueSource(strings = {"cookie", "bearer", "session"})
    void providerSignedTokensAreNotRequestCredentialsOutsideIdTokenMode(@Nullable String authenticationMode) {
        try (MockOpenIdProvider provider = MockOpenIdProvider.start();
             EmbeddedServer server = startRelyingParty(provider, authenticationMode);
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            assertFalse(server.getApplicationContext().containsBean(ReactiveSignatureConfiguration.class),
                "the provider JWKS must not be registered as a signature configuration");
            BlockingHttpClient client = httpClient.toBlocking();
            String idTokenForOtherClient = provider.signedJwt(claims -> claims.subject("watson")
                .audience(OTHER_CLIENT_ID)
                .claim("roles", List.of("ROLE_ADMIN")));
            String idTokenForThisClient = provider.signedJwt(claims -> claims.subject("watson")
                .audience(CLIENT_ID)
                .claim("roles", List.of("ROLE_ADMIN")));
            for (String token : List.of(idTokenForOtherClient, idTokenForThisClient)) {
                assertUnauthorized(client, HttpRequest.GET("/username").bearerAuth(token));
                assertUnauthorized(client, HttpRequest.GET("/username").cookie(Cookie.of("JWT", token)));
                assertUnauthorized(client, HttpRequest.GET("/admin").bearerAuth(token));
                assertUnauthorized(client, HttpRequest.GET("/admin").cookie(Cookie.of("JWT", token)));
            }
        }
    }

    @Test
    void idTokenModeOnlyAcceptsTokensIssuedToThisClient() {
        try (MockOpenIdProvider provider = MockOpenIdProvider.start();
             EmbeddedServer server = startRelyingParty(provider, "idtoken");
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            assertTrue(server.getApplicationContext().containsBean(ReactiveSignatureConfiguration.class));
            BlockingHttpClient client = httpClient.toBlocking();
            String idTokenForOtherClient = provider.signedJwt(claims -> claims.subject("watson")
                .audience(OTHER_CLIENT_ID)
                .claim("roles", List.of("ROLE_ADMIN")));
            assertUnauthorized(client, HttpRequest.GET("/username").bearerAuth(idTokenForOtherClient));
            assertUnauthorized(client, HttpRequest.GET("/admin").cookie(Cookie.of("JWT", idTokenForOtherClient)));

            String idTokenForThisClient = provider.signedJwt(claims -> claims.subject("sherlock")
                .audience(CLIENT_ID)
                .claim("roles", List.of("ROLE_ADMIN")));
            assertEquals("sherlock", client.retrieve(HttpRequest.GET("/username").accept(MediaType.TEXT_PLAIN).bearerAuth(idTokenForThisClient)));
            assertEquals("sherlock", client.retrieve(HttpRequest.GET("/admin").accept(MediaType.TEXT_PLAIN).cookie(Cookie.of("JWT", idTokenForThisClient))));

            String idTokenWithUnknownKey = provider.signedJwtWithUnknownKey(claims -> claims.subject("sherlock").audience(CLIENT_ID));
            assertUnauthorized(client, HttpRequest.GET("/username").bearerAuth(idTokenWithUnknownKey));
        }
    }

    private static EmbeddedServer startRelyingParty(MockOpenIdProvider provider, @Nullable String authenticationMode) {
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("spec.name", SPEC_NAME);
        configuration.put("micronaut.security.redirect.enabled", StringUtils.FALSE);
        configuration.put("micronaut.security.token.jwt.signatures.secret.generator.secret", "pleaseChangeThisSecretForANewOne");
        configuration.put("micronaut.security.oauth2.clients.auth.client-id", CLIENT_ID);
        configuration.put("micronaut.security.oauth2.clients.auth.client-secret", "not-a-real-secret");
        configuration.put("micronaut.security.oauth2.clients.auth.openid.issuer", provider.getIssuer());
        if (authenticationMode != null) {
            configuration.put("micronaut.security.authentication", authenticationMode);
        }
        return ApplicationContext.run(EmbeddedServer.class, configuration);
    }

    private static void assertUnauthorized(BlockingHttpClient client, MutableHttpRequest<?> request) {
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(request.accept(MediaType.TEXT_PLAIN)),
            () -> "GET " + request.getUri() + " should have been rejected");
        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatus(), () -> "GET " + request.getUri());
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller
    @Produces(MediaType.TEXT_PLAIN)
    static class EchoController {
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get("/username")
        String username(Principal principal) {
            return principal.getName();
        }

        @Secured("ROLE_ADMIN")
        @Get("/admin")
        String admin(Principal principal) {
            return principal.getName();
        }
    }
}
