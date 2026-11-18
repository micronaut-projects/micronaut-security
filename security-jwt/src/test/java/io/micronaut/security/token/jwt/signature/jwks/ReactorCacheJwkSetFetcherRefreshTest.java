package io.micronaut.security.token.jwt.signature.jwks;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReactorCacheJwkSetFetcherRefreshTest {

    private static final String URL = "http://localhost/keys";
    private static final String PROVIDER = "foo";

    @Test
    void refreshWhichFailsKeepsTheCachedJwkSet() {
        StubJwksClient client = new StubJwksClient(Mono.just(jwkSet("cached").toString()));
        ReactorCacheJwkSetFetcher fetcher = fetcher(client);
        assertNotNull(fetch(fetcher).orElseThrow().getKeyByKeyId("cached"));

        client.response.set(Mono.error(new IllegalStateException("authorization server is down")));
        assertTrue(refresh(fetcher).isEmpty());
        assertEquals(2, client.invocations.get());

        assertNotNull(fetch(fetcher).orElseThrow().getKeyByKeyId("cached"));
        assertEquals(2, client.invocations.get());
    }

    @Test
    void refreshWhichSucceedsReplacesTheCachedJwkSetWithoutFetchingAgain() {
        StubJwksClient client = new StubJwksClient(Mono.just(jwkSet("cached").toString()));
        ReactorCacheJwkSetFetcher fetcher = fetcher(client);
        assertNotNull(fetch(fetcher).orElseThrow().getKeyByKeyId("cached"));

        client.response.set(Mono.just(jwkSet("rotated").toString()));
        assertNotNull(refresh(fetcher).orElseThrow().getKeyByKeyId("rotated"));
        assertEquals(2, client.invocations.get());

        JWKSet afterRefresh = fetch(fetcher).orElseThrow();
        assertNotNull(afterRefresh.getKeyByKeyId("rotated"));
        assertNull(afterRefresh.getKeyByKeyId("cached"));
        assertEquals(2, client.invocations.get());
    }

    private static ReactorCacheJwkSetFetcher fetcher(JwksClient client) {
        return new ReactorCacheJwkSetFetcher(client, new JwksClientConfigurationProperties(), Map.of());
    }

    private static Optional<JWKSet> fetch(JwkSetFetcher<JWKSet> fetcher) {
        return Mono.from(fetcher.fetch(PROVIDER, URL)).blockOptional();
    }

    private static Optional<JWKSet> refresh(JwkSetFetcher<JWKSet> fetcher) {
        return Mono.from(fetcher.refresh(PROVIDER, URL)).blockOptional();
    }

    private static JWKSet jwkSet(String kid) {
        try {
            return new JWKSet(new RSAKeyGenerator(2048).algorithm(JWSAlgorithm.RS256).keyID(kid).generate().toPublicJWK());
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static final class StubJwksClient implements JwksClient {
        private final AtomicInteger invocations = new AtomicInteger();
        private final AtomicReference<Publisher<String>> response;

        private StubJwksClient(Publisher<String> response) {
            this.response = new AtomicReference<>(response);
        }

        @Override
        public Publisher<String> load(String providerName, String url) {
            invocations.incrementAndGet();
            return response.get();
        }
    }
}
