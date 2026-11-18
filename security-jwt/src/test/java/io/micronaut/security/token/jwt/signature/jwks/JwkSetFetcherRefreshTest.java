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
 * A refresh replaces the cached JWK Set only if the JWK Set can be retrieved. A refresh is triggered by a token with
 * an unknown key ID, which anyone can send: it must not evict the keys which verify the tokens of everybody else
 * while the JWKS endpoint is unavailable.
 */
@SuppressWarnings("removal")
class JwkSetFetcherRefreshTest {

    private static final String PROVIDER = "provider";
    private static final String URL = "https://example.com/.well-known/jwks.json";

    @Test
    void failedRefreshKeepsTheCachedJwkSet() throws Exception {
        RemoteJwks remote = new RemoteJwks(jwkSet("cached"));
        ReactorCacheJwkSetFetcher fetcher = new ReactorCacheJwkSetFetcher(remote, new JwksClientConfigurationProperties(), Map.of());
        assertNotNull(fetch(fetcher).getKeyByKeyId("cached"));
        assertEquals(1, remote.requests.get());

        remote.jwkSet = null;
        JWKSet refreshed = Mono.from(fetcher.refresh(PROVIDER, URL)).block();

        assertNull(refreshed);
        assertEquals(2, remote.requests.get());
        assertNotNull(fetch(fetcher).getKeyByKeyId("cached"));
        assertEquals(2, remote.requests.get());
    }

    @Test
    void successfulRefreshReplacesTheCachedJwkSetWithoutRequestingItTwice() throws Exception {
        RemoteJwks remote = new RemoteJwks(jwkSet("cached"));
        ReactorCacheJwkSetFetcher fetcher = new ReactorCacheJwkSetFetcher(remote, new JwksClientConfigurationProperties(), Map.of());
        fetch(fetcher);

        remote.jwkSet = jwkSet("rotated");
        JWKSet refreshed = Mono.from(fetcher.refresh(PROVIDER, URL)).block();

        assertNotNull(refreshed);
        assertNotNull(refreshed.getKeyByKeyId("rotated"));
        assertEquals(2, remote.requests.get());
        JWKSet cached = fetch(fetcher);
        assertNotNull(cached.getKeyByKeyId("rotated"));
        assertNull(cached.getKeyByKeyId("cached"));
        assertEquals(2, remote.requests.get());
    }

    @Test
    void refreshDoesNotRequestAJwkSetWhichIsBackingOff() {
        RemoteJwks remote = new RemoteJwks(null);
        ReactorCacheJwkSetFetcher fetcher = new ReactorCacheJwkSetFetcher(remote, new JwksClientConfigurationProperties(), Map.of());

        assertNull(Mono.from(fetcher.refresh(PROVIDER, URL)).block());
        assertNull(Mono.from(fetcher.refresh(PROVIDER, URL)).block());

        assertEquals(1, remote.requests.get());
    }

    @Test
    void failedRefreshKeepsTheJwkSetBakedAtBuildTime() throws Exception {
        JWKSet seed = jwkSet("seed");
        RemoteJwks remote = new RemoteJwks(null);
        DefaultJwkSetFetcher.Optimizations optimizations = new DefaultJwkSetFetcher.Optimizations(Map.of(URL, (Supplier<JWKSet>) () -> seed));
        DefaultJwkSetFetcher fetcher = new DefaultJwkSetFetcher(remote, optimizations);

        assertNull(Mono.from(fetcher.refresh(PROVIDER, URL)).block());

        assertEquals(1, remote.requests.get());
        assertTrue(optimizations.findJwkSet(URL).isPresent());
        assertNotNull(fetch(fetcher).getKeyByKeyId("seed"));
        assertEquals(1, remote.requests.get());
    }

    @Test
    void successfulRefreshDiscardsTheJwkSetBakedAtBuildTime() throws Exception {
        JWKSet seed = jwkSet("seed");
        RemoteJwks remote = new RemoteJwks(jwkSet("rotated"));
        DefaultJwkSetFetcher.Optimizations optimizations = new DefaultJwkSetFetcher.Optimizations(Map.of(URL, (Supplier<JWKSet>) () -> seed));
        DefaultJwkSetFetcher fetcher = new DefaultJwkSetFetcher(remote, optimizations);

        JWKSet refreshed = Mono.from(fetcher.refresh(PROVIDER, URL)).block();

        assertNotNull(refreshed);
        assertNotNull(refreshed.getKeyByKeyId("rotated"));
        assertEquals(1, remote.requests.get());
        assertTrue(optimizations.findJwkSet(URL).isEmpty());
        assertNotNull(fetch(fetcher).getKeyByKeyId("rotated"));
    }

    private static JWKSet fetch(JwkSetFetcher<JWKSet> fetcher) {
        JWKSet jwkSet = Mono.from(fetcher.fetch(PROVIDER, URL)).block();
        assertNotNull(jwkSet);
        return jwkSet;
    }

    private static JWKSet jwkSet(String kid) throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .algorithm(JWSAlgorithm.RS256)
                .keyID(kid)
                .generate();
        return new JWKSet(rsaKey.toPublicJWK());
    }

    /**
     * A JWKS endpoint which is unavailable while {@link #jwkSet} is {@code null}.
     */
    private static final class RemoteJwks implements JwksClient {
        private final AtomicInteger requests = new AtomicInteger();
        private volatile JWKSet jwkSet;

        private RemoteJwks(JWKSet jwkSet) {
            this.jwkSet = jwkSet;
        }

        @Override
        public Mono<String> load(String providerName, String url) {
            requests.incrementAndGet();
            JWKSet current = jwkSet;
            return current == null ? Mono.error(new IllegalStateException("JWKS endpoint unavailable")) : Mono.just(current.toString());
        }
    }
}
