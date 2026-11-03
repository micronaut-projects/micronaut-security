package io.micronaut.security.token.jwt.signature.jwks;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The JWKS baked at build time by the AOT optimizations is only an initial seed. Once the cache is cleared for the url,
 * the JWKS must be fetched over the network.
 */
class DefaultJwkSetFetcherSeedTest {

    private static final String URL = "https://example.com/.well-known/jwks.json";
    private static final String OTHER_URL = "https://other.example.com/.well-known/jwks.json";

    @Test
    void clearCacheOnSeededUrlLeadsToNetworkFetch() throws Exception {
        JWKSet seeded = jwkSet("seed");
        JWKSet remote = jwkSet("remote");
        AtomicInteger networkFetches = new AtomicInteger();
        JwksClient jwksClient = (providerName, url) -> {
            networkFetches.incrementAndGet();
            return Mono.just(remote.toString());
        };
        DefaultJwkSetFetcher.Optimizations optimizations = new DefaultJwkSetFetcher.Optimizations(Map.of(URL, (Supplier<JWKSet>) () -> seeded));
        DefaultJwkSetFetcher fetcher = new DefaultJwkSetFetcher(jwksClient, optimizations) { };

        // the baked JWKS is used as the initial seed
        JWKSet first = Mono.from(fetcher.fetch("provider", URL)).block();
        assertNotNull(first);
        assertNotNull(first.getKeyByKeyId("seed"));
        assertNull(first.getKeyByKeyId("remote"));
        assertEquals(0, networkFetches.get());

        // clearing the cache discards the seed and the next fetch goes to the network
        fetcher.clearCache(URL);
        JWKSet second = Mono.from(fetcher.fetch("provider", URL)).block();
        assertNotNull(second);
        assertNotNull(second.getKeyByKeyId("remote"));
        assertNull(second.getKeyByKeyId("seed"));
        assertEquals(1, networkFetches.get());

        // the seed is not resurrected
        Mono.from(fetcher.fetch("provider", URL)).block();
        assertEquals(2, networkFetches.get());
        assertTrue(optimizations.findJwkSet(URL).isEmpty());
    }

    @Test
    void clearCacheWithProviderNameOnSeededUrlLeadsToNetworkFetch() throws Exception {
        JWKSet seeded = jwkSet("seed");
        JWKSet remote = jwkSet("remote");
        AtomicInteger networkFetches = new AtomicInteger();
        JwksClient jwksClient = (providerName, url) -> {
            networkFetches.incrementAndGet();
            return Mono.just(remote.toString());
        };
        DefaultJwkSetFetcher.Optimizations optimizations = new DefaultJwkSetFetcher.Optimizations(Map.of(URL, (Supplier<JWKSet>) () -> seeded));
        DefaultJwkSetFetcher fetcher = new DefaultJwkSetFetcher(jwksClient, optimizations) { };

        assertNotNull(Mono.from(fetcher.fetch("provider", URL)).block().getKeyByKeyId("seed"));
        assertEquals(0, networkFetches.get());

        fetcher.clearCache("provider", URL);
        assertNotNull(Mono.from(fetcher.fetch("provider", URL)).block().getKeyByKeyId("remote"));
        assertEquals(1, networkFetches.get());
    }

    @Test
    void clearCacheOnUnknownUrlIsNoOpAndUrlsWithoutSeedAlwaysGoToNetwork() throws Exception {
        JWKSet seeded = jwkSet("seed");
        JWKSet remote = jwkSet("remote");
        AtomicInteger networkFetches = new AtomicInteger();
        JwksClient jwksClient = (providerName, url) -> {
            networkFetches.incrementAndGet();
            return Mono.just(remote.toString());
        };
        DefaultJwkSetFetcher.Optimizations optimizations = new DefaultJwkSetFetcher.Optimizations(Map.of(URL, (Supplier<JWKSet>) () -> seeded));
        DefaultJwkSetFetcher fetcher = new DefaultJwkSetFetcher(jwksClient, optimizations) { };

        fetcher.clearCache(OTHER_URL);
        assertNotNull(Mono.from(fetcher.fetch("provider", OTHER_URL)).block().getKeyByKeyId("remote"));
        assertEquals(1, networkFetches.get());

        // the seed of the other url is untouched
        assertTrue(optimizations.findJwkSet(URL).isPresent());
        assertNotNull(Mono.from(fetcher.fetch("provider", URL)).block().getKeyByKeyId("seed"));
        assertEquals(1, networkFetches.get());
    }

    private static JWKSet jwkSet(String kid) throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .algorithm(JWSAlgorithm.RS256)
                .keyID(kid)
                .generate();
        return new JWKSet(rsaKey.toPublicJWK());
    }
}
