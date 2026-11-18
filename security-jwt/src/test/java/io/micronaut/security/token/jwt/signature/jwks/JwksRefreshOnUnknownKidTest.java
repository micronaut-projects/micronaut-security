package io.micronaut.security.token.jwt.signature.jwks;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
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
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * When a JWT carries a kid which is not present in the cached JWKS, the JWKS is fetched again (rate limited)
 * without waiting for the cache to expire.
 */
class JwksRefreshOnUnknownKidTest {

    private static final String SPEC_NAME = "JwksRefreshOnUnknownKidTest";
    private static final String AUTH_SERVER_SPEC_NAME = SPEC_NAME + ".authServer";
    private static final String UNKNOWN_KEY_ID = "unknown-kid";

    private static EmbeddedServer authServer;
    private static RotatingKeys keys;

    private EmbeddedServer server;
    private HttpClient httpClient;
    private BlockingHttpClient client;

    static Stream<Arguments> caches() {
        return Stream.of(
                arguments("reactor cache", Map.of()),
                arguments("micronaut cache", Map.of("micronaut.caches.jwks.expire-after-write", "1h")));
    }

    @BeforeAll
    static void startAuthServer() {
        authServer = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", AUTH_SERVER_SPEC_NAME));
        keys = authServer.getApplicationContext().getBean(RotatingKeys.class);
    }

    @AfterAll
    static void stopAuthServer() {
        authServer.close();
    }

    @BeforeEach
    void resetKeys() {
        keys.reset();
    }

    @AfterEach
    void stopServer() {
        if (httpClient != null) {
            httpClient.close();
        }
        if (server != null) {
            server.close();
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("caches")
    void tokenSignedWithARotatedKeyIsAcceptedAfterExactlyOneExtraJwksFetch(String description, Map<String, Object> cacheConfiguration) {
        startServer(cacheConfiguration);
        String token = sign(keys.current);

        assertEquals(HttpStatus.OK, hello(token));
        assertEquals(1, keys.requests.get(), "the JWKS is fetched once");

        assertEquals(HttpStatus.OK, hello(token));
        assertEquals(1, keys.requests.get(), "the JWKS is cached");

        String rotatedToken = sign(keys.rotate());

        assertEquals(HttpStatus.OK, hello(rotatedToken));
        assertEquals(2, keys.requests.get(), "the JWKS is fetched exactly once more without waiting for the cache to expire");

        assertEquals(HttpStatus.OK, hello(rotatedToken));
        assertEquals(2, keys.requests.get(), "the refreshed JWKS is cached");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("caches")
    void tokensWithAnUnknownKeyIdTriggerAtMostOneJwksFetchWithinTheRefreshInterval(String description, Map<String, Object> cacheConfiguration) throws Exception {
        startServer(cacheConfiguration);
        String unknownToken = sign(generateKey(UNKNOWN_KEY_ID));
        hello(sign(keys.current));
        assertEquals(1, keys.requests.get());

        for (int i = 0; i < 5; i++) {
            assertEquals(HttpStatus.UNAUTHORIZED, hello(unknownToken));
        }
        assertEquals(2, keys.requests.get(), "sequential requests with an unknown kid fetch the JWKS only once more");

        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<Future<HttpStatus>> burst = new ArrayList<>();
            for (int i = 0; i < 16; i++) {
                burst.add(executor.submit(() -> hello(unknownToken)));
            }
            for (Future<HttpStatus> status : burst) {
                assertEquals(HttpStatus.UNAUTHORIZED, status.get(30, TimeUnit.SECONDS));
            }
        } finally {
            executor.shutdownNow();
        }
        assertEquals(2, keys.requests.get(), "a burst of concurrent requests with an unknown kid does not fetch the JWKS again");

        String forgedToken = sign(generateKey(keys.current.getKeyID()));

        assertEquals(HttpStatus.UNAUTHORIZED, hello(forgedToken));
        assertEquals(2, keys.requests.get(), "a known kid with an invalid signature does not trigger a refresh");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("caches")
    void tokensSignedWithTheCachedKeyAreStillAcceptedIfTheRefreshFails(String description, Map<String, Object> cacheConfiguration) {
        startServer(cacheConfiguration);
        String token = sign(keys.current);
        assertEquals(HttpStatus.OK, hello(token));
        assertEquals(1, keys.requests.get());

        keys.available = false;

        assertEquals(HttpStatus.UNAUTHORIZED, hello(sign(generateKey(UNKNOWN_KEY_ID))));
        assertEquals(2, keys.requests.get(), "the unknown kid triggers a refresh, which fails");

        assertEquals(HttpStatus.OK, hello(token), "the failed refresh must not evict the cached JWKS");
        assertEquals(2, keys.requests.get());
    }

    @Test
    void tokenWithoutKeyIdDoesNotTriggerAJwksRefresh() {
        startServer(Map.of());
        hello(sign(keys.current));
        assertEquals(1, keys.requests.get());

        assertEquals(HttpStatus.UNAUTHORIZED, hello(sign(generateKey("other"), false)));
        assertEquals(1, keys.requests.get(), "a token without kid signed with an unknown key does not fetch the JWKS again");

        assertEquals(HttpStatus.OK, hello(sign(keys.current, false)));
        assertEquals(1, keys.requests.get(), "a token without kid signed with the current key is verified with the cached JWKS");
    }

    @Test
    void refreshIntervalIsConfigurable() {
        startServer(Map.of("micronaut.security.token.jwt.signatures.jwks.rotating.refresh-interval", "1m"));

        assertEquals(Duration.ofMinutes(1), server.getApplicationContext().getBean(JwksSignatureConfiguration.class).getRefreshInterval());
    }

    @Test
    void refreshIntervalDefaultsToThirtySeconds() {
        startServer(Map.of());

        assertEquals(Duration.ofSeconds(30), server.getApplicationContext().getBean(JwksSignatureConfiguration.class).getRefreshInterval());
    }

    private void startServer(Map<String, Object> extra) {
        Map<String, Object> configuration = new HashMap<>(extra);
        configuration.put("spec.name", SPEC_NAME);
        configuration.put("micronaut.http.client.read-timeout", "30s");
        configuration.put("micronaut.security.authentication", "bearer");
        configuration.put("micronaut.security.token.jwt.signatures.jwks.rotating.url", "http://localhost:" + authServer.getPort() + "/jwks");
        configuration.put("micronaut.security.token.jwt.signatures.jwks.rotating.cache-expiration", 3600);
        server = ApplicationContext.run(EmbeddedServer.class, configuration);
        httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
        client = httpClient.toBlocking();
    }

    private HttpStatus hello(String token) {
        try {
            return client.exchange(HttpRequest.GET("/hello").bearerAuth(token), String.class).status();
        } catch (HttpClientResponseException e) {
            return e.getStatus();
        }
    }

    private static RSAKey generateKey(String keyId) {
        try {
            return new RSAKeyGenerator(2048)
                    .algorithm(JWSAlgorithm.RS256)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(keyId)
                    .generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String sign(RSAKey rsaKey) {
        return sign(rsaKey, true);
    }

    private static String sign(RSAKey rsaKey, boolean includeKeyId) {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("sherlock")
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .build();
        JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.RS256);
        if (includeKeyId) {
            header.keyID(rsaKey.getKeyID());
        }
        SignedJWT signedJWT = new SignedJWT(header.build(), claimsSet);
        try {
            signedJWT.sign(new RSASSASigner(rsaKey));
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
        return signedJWT.serialize();
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller("/hello")
    static class HelloWorldController {
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        @Secured(SecurityRule.IS_AUTHENTICATED)
        String index() {
            return "Hello World";
        }
    }

    /**
     * The signing key of the authorization server, which can be rotated, and the availability of its JWKS endpoint.
     */
    @Requires(property = "spec.name", value = AUTH_SERVER_SPEC_NAME)
    @Singleton
    static class RotatingKeys {
        final AtomicInteger requests = new AtomicInteger();
        private final AtomicInteger generation = new AtomicInteger();
        volatile RSAKey current;
        volatile boolean available;

        RSAKey rotate() {
            current = generateKey("kid-" + generation.incrementAndGet());
            return current;
        }

        void reset() {
            rotate();
            available = true;
            requests.set(0);
        }
    }

    @Requires(property = "spec.name", value = AUTH_SERVER_SPEC_NAME)
    @Controller("/jwks")
    static class JwksController {
        private final RotatingKeys keys;

        JwksController(RotatingKeys keys) {
            this.keys = keys;
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.APPLICATION_JSON)
        @Get
        HttpResponse<String> index() {
            keys.requests.incrementAndGet();
            if (!keys.available) {
                return HttpResponse.serverError();
            }
            return HttpResponse.ok(new JWKSet(keys.current.toPublicJWK()).toString());
        }
    }
}
