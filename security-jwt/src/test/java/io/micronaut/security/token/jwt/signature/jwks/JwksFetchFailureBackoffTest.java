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
package io.micronaut.security.token.jwt.signature.jwks;

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
import io.micronaut.context.env.Environment;
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
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * A failed JWK Set retrieval must not be retried for every bearer token presented to the application.
 */
class JwksFetchFailureBackoffTest {

    /**
     * Not a credential: a string which merely parses as a signed JWT ({"alg":"RS256"} header, empty payload, garbage signature).
     */
    private static final String PARSEABLE_SIGNED_JWT = "eyJhbGciOiJSUzI1NiJ9.e30.AAAA";

    private static final String FAILURE_BACKOFF_PROPERTY = "micronaut.security.token.jwt.signatures.jwks-client.failure-backoff";

    @Test
    void failingJwksEndpointIsRequestedOncePerBackoffWindow() {
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class, authServerConfig(null))) {
            KeysController keysController = authServer.getApplicationContext().getBean(KeysController.class);
            try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, resourceServerConfig(authServer))) {
                assertTrue(server.getApplicationContext().getBean(JwkSetFetcher.class) instanceof DefaultJwkSetFetcher);
                BlockingHttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();

                for (int i = 0; i < 5; i++) {
                    assertUnauthorized(client, PARSEABLE_SIGNED_JWT);
                }
                assertEquals(1, keysController.invocations.get(), "the failing JWKS endpoint must be requested once per back-off window");
            }
        }
    }

    @Test
    void jwksWithoutKeysIsRequestedOncePerBackoffWindow() {
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class, authServerConfig("{\"keys\":[]}"))) {
            KeysController keysController = authServer.getApplicationContext().getBean(KeysController.class);
            keysController.failing.set(false);
            try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, resourceServerConfig(authServer))) {
                BlockingHttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();

                for (int i = 0; i < 5; i++) {
                    assertUnauthorized(client, PARSEABLE_SIGNED_JWT);
                }
                assertEquals(1, keysController.invocations.get(), "a JWK Set without keys must not be requested again before the back-off elapses");
            }
        }
    }

    @Test
    void backoffCanBeDisabled() {
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class, authServerConfig(null))) {
            KeysController keysController = authServer.getApplicationContext().getBean(KeysController.class);
            Map<String, Object> config = resourceServerConfig(authServer);
            config.put(FAILURE_BACKOFF_PROPERTY, "0s");
            try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, config)) {
                BlockingHttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();

                for (int i = 0; i < 5; i++) {
                    assertUnauthorized(client, PARSEABLE_SIGNED_JWT);
                }
                assertEquals(5, keysController.invocations.get());
            }
        }
    }

    @Test
    void validTokenIsAcceptedOnceTheBackoffElapsesAndTheJwksEndpointRecovers() throws JOSEException, InterruptedException {
        RSAKey rsaKey = new RSAKeyGenerator(2048).keyID("test-kid").algorithm(JWSAlgorithm.RS256).generate();
        String jwksJson = new JWKSet(rsaKey.toPublicJWK()).toString(true);
        String token = signedJwt(rsaKey);
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class, authServerConfig(jwksJson))) {
            KeysController keysController = authServer.getApplicationContext().getBean(KeysController.class);
            Map<String, Object> config = resourceServerConfig(authServer);
            config.put(FAILURE_BACKOFF_PROPERTY, "1s");
            try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, config)) {
                BlockingHttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();

                // JWKS endpoint failing: the token cannot be verified
                assertUnauthorized(client, token);
                assertEquals(1, keysController.invocations.get());

                // the JWKS endpoint recovers but the back-off has not elapsed: no request is made, the token is still rejected
                keysController.failing.set(false);
                assertUnauthorized(client, token);
                assertEquals(1, keysController.invocations.get());

                // once the back-off elapses the JWKS is fetched again and the token is accepted
                awaitAccepted(client, token, Duration.ofSeconds(10));
                assertEquals(2, keysController.invocations.get());

                // the successful JWKS is cached by the signature configuration, no further request is made
                assertEquals("Hello World", client.retrieve(HttpRequest.GET("/hello").bearerAuth(token)));
                assertEquals(2, keysController.invocations.get());

                // clearing the signature configuration cache discards the cached JWKS and the next token triggers a retrieval
                server.getApplicationContext().getBean(JwksCache.class).clear();
                assertEquals("Hello World", client.retrieve(HttpRequest.GET("/hello").bearerAuth(token)));
                assertEquals(3, keysController.invocations.get());
            }
        }
    }

    /**
     * Retries the request until the token is accepted. Requests rejected while the url is backing off do not contact the JWKS endpoint.
     */
    private static void awaitAccepted(BlockingHttpClient client, String token, Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (true) {
            try {
                assertEquals("Hello World", client.retrieve(HttpRequest.GET("/hello").bearerAuth(token)));
                return;
            } catch (HttpClientResponseException e) {
                assertEquals(HttpStatus.UNAUTHORIZED, e.getStatus());
                if (System.nanoTime() - deadline >= 0) {
                    fail("token not accepted within " + timeout);
                }
                Thread.sleep(100);
            }
        }
    }

    private static void assertUnauthorized(BlockingHttpClient client, String token) {
        HttpRequest<?> request = HttpRequest.GET("/hello").bearerAuth(token);
        HttpClientResponseException e = assertThrows(HttpClientResponseException.class, () -> client.retrieve(request));
        assertEquals(HttpStatus.UNAUTHORIZED, e.getStatus());
    }

    private static Map<String, Object> authServerConfig(String jwksJson) {
        Map<String, Object> config = new HashMap<>();
        config.put("spec.name", "JwksFetchFailureBackoffTestAuthServer");
        if (jwksJson != null) {
            config.put("jwks.json", jwksJson);
        }
        return config;
    }

    private static Map<String, Object> resourceServerConfig(EmbeddedServer authServer) {
        Map<String, Object> config = new HashMap<>();
        config.put("spec.name", "JwksFetchFailureBackoffTest");
        config.put("micronaut.security.token.jwt.signatures.jwks.foo.url", jwksUrl(authServer));
        return config;
    }

    private static String jwksUrl(EmbeddedServer authServer) {
        return "http://localhost:" + authServer.getPort() + "/keys";
    }

    private static String signedJwt(RSAKey rsaKey) throws JOSEException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .subject("sherlock")
            .issueTime(Date.from(Instant.now()))
            .expirationTime(Date.from(Instant.now().plusSeconds(300)))
            .build();
        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(), claimsSet);
        signedJWT.sign(new RSASSASigner(rsaKey.toPrivateKey()));
        return signedJWT.serialize();
    }

    @Requires(property = "spec.name", value = "JwksFetchFailureBackoffTest")
    @Controller("/hello")
    static class HelloController {
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String index() {
            return "Hello World";
        }
    }

    @Requires(property = "spec.name", value = "JwksFetchFailureBackoffTestAuthServer")
    @Controller("/keys")
    static class KeysController {
        final AtomicInteger invocations = new AtomicInteger();
        final AtomicBoolean failing = new AtomicBoolean(true);
        private final String jwksJson;

        KeysController(Environment environment) {
            this.jwksJson = environment.getProperty("jwks.json", String.class).orElse("{\"keys\":[]}");
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.APPLICATION_JSON)
        @Get
        HttpResponse<String> keys() {
            invocations.incrementAndGet();
            return failing.get() ? HttpResponse.serverError() : HttpResponse.ok(jwksJson);
        }
    }
}
