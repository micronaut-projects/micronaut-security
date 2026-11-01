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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.jwt.signature.ReactiveSignatureConfiguration;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * An application whose only source of JWT verification keys is an OpenID provider must keep rejecting unsigned
 * tokens when the provider's discovery document cannot be fetched at startup, and it must start verifying signed
 * tokens once the provider becomes reachable, without a restart.
 */
class OpenIdProviderUnavailableAtStartupTest {
    private static final String AUTH_SERVER = "OpenIdProviderUnavailableAtStartupTestAuthServer";
    private static final String APP = "OpenIdProviderUnavailableAtStartupTestApp";
    private static final String CLIENT_ID = "myclient";

    @Test
    void unsignedTokensAreRejectedWhenDiscoveryFailsAtStartup() throws Exception {
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", AUTH_SERVER))) {
            ProviderState provider = authServer.getApplicationContext().getBean(ProviderState.class);
            provider.available = false;
            String issuer = issuer(authServer);
            try (EmbeddedServer app = startApp(issuer, "idtoken");
                 HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
                BlockingHttpClient client = httpClient.toBlocking();
                assertFalse(app.getApplicationContext().getBeansOfType(ReactiveSignatureConfiguration.class).isEmpty(),
                    "the OpenID provider JWKS must stay registered as a signature configuration although discovery failed");

                JwksSignatureConfiguration jwks = app.getApplicationContext().getBean(JwksSignatureConfiguration.class, Qualifiers.byName("authserver"));
                assertEquals(issuer, jwks.getIssuer(), "the JWKS is bound to the configured issuer while the provider is down");
                assertThrows(IllegalStateException.class, jwks::getUrl);

                String unsigned = new PlainJWT(claims(issuer, "attacker")).serialize();
                assertUnauthorized(client, unsigned);

                String signed = sign(provider.key, claims(issuer, "alice"));
                assertUnauthorized(client, signed);

                String signedForAnotherIssuer = sign(provider.key, claims("https://other.example/oauth2/default", "mallory"));
                assertUnauthorized(client, signedForAnotherIssuer);

                provider.available = true;
                assertEventuallyAuthenticated(client, signed, "alice");
                assertUnauthorized(client, unsigned);
                assertUnauthorized(client, signedForAnotherIssuer);
                assertEquals(issuer, jwks.getIssuer());
                assertEquals(issuer + "/keys", jwks.getUrl());
            }
        }
    }

    @Test
    void signedTokensAreAcceptedAndUnsignedTokensRejectedWhenDiscoverySucceedsAtStartup() throws Exception {
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", AUTH_SERVER))) {
            ProviderState provider = authServer.getApplicationContext().getBean(ProviderState.class);
            String issuer = issuer(authServer);
            try (EmbeddedServer app = startApp(issuer, "idtoken");
                 HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
                BlockingHttpClient client = httpClient.toBlocking();
                String signed = sign(provider.key, claims(issuer, "alice"));
                assertEquals("alice", client.retrieve(HttpRequest.GET("/").bearerAuth(signed)));
                assertUnauthorized(client, new PlainJWT(claims(issuer, "attacker")).serialize());
            }
        }
    }

    @Test
    void discoveryRequestsAreBackedOffWhileTheProviderIsUnavailable() throws Exception {
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", AUTH_SERVER))) {
            ProviderState provider = authServer.getApplicationContext().getBean(ProviderState.class);
            provider.available = false;
            String issuer = issuer(authServer);
            try (EmbeddedServer app = startApp(issuer, "idtoken");
                 HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
                BlockingHttpClient client = httpClient.toBlocking();
                String signed = sign(provider.key, claims(issuer, "alice"));
                assertUnauthorized(client, signed);
                int afterFirst = provider.discoveryRequests.get();
                for (int i = 0; i < 50; i++) {
                    assertUnauthorized(client, signed);
                }
                assertTrue(provider.discoveryRequests.get() - afterFirst <= 2,
                    "discovery requests must be backed off while the provider is down, got " + (provider.discoveryRequests.get() - afterFirst));
            }
        }
    }

    @Test
    void disabledClientRegistersNoJwksEvenWhenTheProviderIsUnavailable() throws Exception {
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", AUTH_SERVER))) {
            ProviderState provider = authServer.getApplicationContext().getBean(ProviderState.class);
            provider.available = false;
            String issuer = issuer(authServer);
            try (EmbeddedServer app = ApplicationContext.run(EmbeddedServer.class, Map.of(
                    "spec.name", APP,
                    "micronaut.security.authentication", "idtoken",
                    "micronaut.security.oauth2.clients.authserver.enabled", false,
                    "micronaut.security.oauth2.clients.authserver.client-id", CLIENT_ID,
                    "micronaut.security.oauth2.clients.authserver.client-secret", "test-fixture-not-a-secret",
                    "micronaut.security.oauth2.clients.authserver.openid.issuer", issuer));
                 HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
                assertTrue(app.getApplicationContext().getBeansOfType(JwksSignatureConfiguration.class).isEmpty());
                BlockingHttpClient client = httpClient.toBlocking();
                assertUnauthorized(client, new PlainJWT(claims(issuer, "attacker")).serialize());
                provider.available = true;
                assertUnauthorized(client, sign(provider.key, claims(issuer, "alice")));
            }
        }
    }

    @Test
    void providerJwksIsNotRegisteredAsRequestSignatureInBearerMode() throws Exception {
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", AUTH_SERVER))) {
            ProviderState provider = authServer.getApplicationContext().getBean(ProviderState.class);
            String issuer = issuer(authServer);
            try (EmbeddedServer app = startApp(issuer, "bearer");
                 HttpClient httpClient = app.getApplicationContext().createBean(HttpClient.class, app.getURL())) {
                assertTrue(app.getApplicationContext().getBeansOfType(JwksSignatureConfiguration.class).isEmpty());
                assertUnauthorized(httpClient.toBlocking(), sign(provider.key, claims(issuer, "alice")));
            }
        }
    }

    private static EmbeddedServer startApp(String issuer, String authentication) {
        return ApplicationContext.run(EmbeddedServer.class, Map.of(
            "spec.name", APP,
            "micronaut.security.authentication", authentication,
            // the discovery document is requested again at most once per back-off; a short one keeps the test fast
            "micronaut.security.token.jwt.signatures.jwks-client.failure-backoff", "1s",
            "micronaut.security.oauth2.clients.authserver.client-id", CLIENT_ID,
            "micronaut.security.oauth2.clients.authserver.client-secret", "test-fixture-not-a-secret",
            "micronaut.security.oauth2.clients.authserver.openid.issuer", issuer));
    }

    private static String issuer(EmbeddedServer authServer) {
        return "http://localhost:" + authServer.getPort() + "/oauth2/default";
    }

    private static void assertUnauthorized(BlockingHttpClient client, String token) {
        HttpClientResponseException e = assertThrows(HttpClientResponseException.class,
            () -> client.retrieve(HttpRequest.GET("/").bearerAuth(token)));
        assertEquals(HttpStatus.UNAUTHORIZED, e.getStatus());
    }

    private static void assertEventuallyAuthenticated(BlockingHttpClient client, String token, String expected) throws InterruptedException {
        Instant deadline = Instant.now().plus(Duration.ofSeconds(30));
        while (true) {
            try {
                assertEquals(expected, client.retrieve(HttpRequest.GET("/").bearerAuth(token)));
                return;
            } catch (HttpClientResponseException e) {
                if (e.getStatus() != HttpStatus.UNAUTHORIZED || Instant.now().isAfter(deadline)) {
                    fail("signed token was not accepted after the provider became available; last status " + e.getStatus());
                }
                Thread.sleep(200);
            }
        }
    }

    private static JWTClaimsSet claims(String issuer, String subject) {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject(subject)
            .audience(CLIENT_ID)
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plus(Duration.ofHours(1))))
            .claim("roles", List.of("ROLE_ADMIN"))
            .build();
    }

    private static String sign(RSAKey key, JWTClaimsSet claims) throws JOSEException {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    @Requires(property = "spec.name", value = AUTH_SERVER)
    @Singleton
    static class ProviderState {
        final RSAKey key;
        volatile boolean available = true;
        final AtomicInteger discoveryRequests = new AtomicInteger();

        ProviderState() throws JOSEException {
            this.key = new RSAKeyGenerator(2048).keyID("test-key").generate();
        }
    }

    @Requires(property = "spec.name", value = AUTH_SERVER)
    @Controller("/oauth2/default")
    static class MockOpenIdProviderController {
        private final ProviderState state;
        private final EmbeddedServer embeddedServer;

        MockOpenIdProviderController(ProviderState state, EmbeddedServer embeddedServer) {
            this.state = state;
            this.embeddedServer = embeddedServer;
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/.well-known/openid-configuration")
        HttpResponse<String> configuration() {
            state.discoveryRequests.incrementAndGet();
            if (!state.available) {
                return HttpResponse.status(HttpStatus.SERVICE_UNAVAILABLE);
            }
            String issuer = issuer(embeddedServer);
            return HttpResponse.ok("""
                {
                  "issuer": "%s",
                  "authorization_endpoint": "%s/authorize",
                  "token_endpoint": "%s/token",
                  "jwks_uri": "%s/keys",
                  "response_types_supported": ["code"],
                  "subject_types_supported": ["public"],
                  "id_token_signing_alg_values_supported": ["RS256"]
                }
                """.formatted(issuer, issuer, issuer, issuer)).contentType(MediaType.APPLICATION_JSON_TYPE);
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/keys")
        HttpResponse<String> keys() {
            if (!state.available) {
                return HttpResponse.status(HttpStatus.SERVICE_UNAVAILABLE);
            }
            return HttpResponse.ok(new JWKSet(state.key.toPublicJWK()).toString()).contentType(MediaType.APPLICATION_JSON_TYPE);
        }
    }

    @Requires(property = "spec.name", value = APP)
    @Controller("/")
    static class HomeController {
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String index(Principal principal) {
            return principal.getName();
        }
    }
}
