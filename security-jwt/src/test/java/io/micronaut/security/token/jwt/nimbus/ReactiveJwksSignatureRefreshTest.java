package io.micronaut.security.token.jwt.nimbus;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.security.token.jwt.signature.jwks.DefaultJwkValidator;
import io.micronaut.security.token.jwt.signature.jwks.JwkSetFetcher;
import io.micronaut.security.token.jwt.signature.jwks.JwksClientReactorContext;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfigurationProperties;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReactiveJwksSignatureRefreshTest {
    private static final String URL = "http://localhost:8081/keys";
    private static final RSAKey CACHED_KEY = generateKey("cached");
    private static final RSAKey ROTATED_KEY = generateKey("rotated");

    @Test
    void refreshWhichFailsRejectsTheTokenAndKeepsVerifyingWithTheCachedKeys() {
        StubJwkSetFetcher fetcher = new StubJwkSetFetcher(new JWKSet(CACHED_KEY.toPublicJWK()));
        fetcher.refresh.set(Mono.empty());
        ReactiveJwksSignature signature = signature(fetcher);

        assertFalse(verify(signature, signedJwt(ROTATED_KEY)));
        assertEquals(1, fetcher.refreshes.get());
        assertEquals(0, fetcher.cacheClears.get());
        assertTrue(verify(signature, signedJwt(CACHED_KEY)));
    }

    @Test
    void refreshWhichSucceedsVerifiesTheTokenWithTheRetrievedKeys() {
        StubJwkSetFetcher fetcher = new StubJwkSetFetcher(new JWKSet(CACHED_KEY.toPublicJWK()));
        fetcher.refresh.set(Mono.just(new JWKSet(ROTATED_KEY.toPublicJWK())));
        ReactiveJwksSignature signature = signature(fetcher);

        assertTrue(verify(signature, signedJwt(ROTATED_KEY)));
        assertEquals(1, fetcher.refreshes.get());
    }

    @Test
    void tokensArrivingWhileTheRefreshIsInFlightJoinItInsteadOfBeingRateLimited() {
        StubJwkSetFetcher fetcher = new StubJwkSetFetcher(new JWKSet(CACHED_KEY.toPublicJWK()));
        Sinks.One<JWKSet> retrieval = Sinks.one();
        fetcher.refresh.set(retrieval.asMono());
        ReactiveJwksSignature signature = signature(fetcher);

        CompletableFuture<Boolean> first = verifyAsync(signature, signedJwt(ROTATED_KEY));
        CompletableFuture<Boolean> second = verifyAsync(signature, signedJwt(ROTATED_KEY));
        assertFalse(first.isDone());
        assertFalse(second.isDone());

        retrieval.tryEmitValue(new JWKSet(ROTATED_KEY.toPublicJWK()));

        assertTrue(first.join());
        assertTrue(second.join());
        assertEquals(1, fetcher.refreshes.get());
    }

    @Test
    void unknownKeyIdDoesNotRefreshAgainWithinTheRefreshInterval() {
        StubJwkSetFetcher fetcher = new StubJwkSetFetcher(new JWKSet(CACHED_KEY.toPublicJWK()));
        fetcher.refresh.set(Mono.empty());
        ReactiveJwksSignature signature = signature(fetcher);

        for (int i = 0; i < 5; i++) {
            assertFalse(verify(signature, signedJwt(ROTATED_KEY)));
        }
        assertEquals(1, fetcher.refreshes.get());
    }

    @Test
    void unknownKeyIdRefreshesAgainOnceTheRefreshIntervalElapses() {
        StubJwkSetFetcher fetcher = new StubJwkSetFetcher(new JWKSet(CACHED_KEY.toPublicJWK()));
        AtomicLong nanoTime = new AtomicLong();
        ReactiveJwksSignature signature = signature(fetcher, Duration.ofSeconds(30), nanoTime::get);

        assertFalse(verify(signature, signedJwt(ROTATED_KEY)));
        assertEquals(1, fetcher.refreshes.get());

        nanoTime.addAndGet(Duration.ofSeconds(29).toNanos());
        assertFalse(verify(signature, signedJwt(ROTATED_KEY)));
        assertEquals(1, fetcher.refreshes.get());

        nanoTime.addAndGet(Duration.ofSeconds(1).toNanos());
        assertFalse(verify(signature, signedJwt(ROTATED_KEY)));
        assertEquals(2, fetcher.refreshes.get());
    }

    @Test
    void refreshIntervalTooLongToBeExpressedInNanosecondsAllowsTheFirstRefreshOnly() {
        StubJwkSetFetcher fetcher = new StubJwkSetFetcher(new JWKSet(CACHED_KEY.toPublicJWK()));
        ReactiveJwksSignature signature = signature(fetcher, Duration.ofSeconds(Long.MAX_VALUE));

        assertFalse(verify(signature, signedJwt(ROTATED_KEY)));
        assertFalse(verify(signature, signedJwt(ROTATED_KEY)));
        assertEquals(1, fetcher.refreshes.get());
    }

    @Test
    void negativeRefreshIntervalDisablesTheRateLimit() {
        StubJwkSetFetcher fetcher = new StubJwkSetFetcher(new JWKSet(CACHED_KEY.toPublicJWK()));
        ReactiveJwksSignature signature = signature(fetcher, Duration.ofSeconds(-1));

        assertFalse(verify(signature, signedJwt(ROTATED_KEY)));
        assertFalse(verify(signature, signedJwt(ROTATED_KEY)));
        assertEquals(2, fetcher.refreshes.get());
    }

    @Test
    void unknownKeyIdDoesNotRefreshUnlessTheReactorContextAllowsIt() {
        StubJwkSetFetcher fetcher = new StubJwkSetFetcher(new JWKSet(CACHED_KEY.toPublicJWK()));
        ReactiveJwksSignature signature = signature(fetcher);

        assertFalse(Boolean.TRUE.equals(Mono.from(signature.verify(signedJwt(ROTATED_KEY))).block()));
        assertEquals(0, fetcher.refreshes.get());
    }

    private static ReactiveJwksSignature signature(JwkSetFetcher<JWKSet> fetcher) {
        return signature(fetcher, Duration.ofHours(1));
    }

    private static ReactiveJwksSignature signature(JwkSetFetcher<JWKSet> fetcher, Duration refreshInterval) {
        return signature(fetcher, refreshInterval, System::nanoTime);
    }

    private static ReactiveJwksSignature signature(JwkSetFetcher<JWKSet> fetcher, Duration refreshInterval, LongSupplier nanoTime) {
        JwksSignatureConfigurationProperties configuration = new JwksSignatureConfigurationProperties("test");
        configuration.setUrl(URL);
        configuration.setRefreshInterval(refreshInterval);
        return new ReactiveJwksSignature(configuration, new DefaultJwkValidator(), fetcher, nanoTime);
    }

    private static boolean verify(ReactiveJwksSignature signature, SignedJWT jwt) {
        return verifyAsync(signature, jwt).join();
    }

    private static CompletableFuture<Boolean> verifyAsync(ReactiveJwksSignature signature, SignedJWT jwt) {
        JwksClientReactorContext context = new JwksClientReactorContext();
        context.allowRefreshOnUnknownKeyId();
        return Mono.from(signature.verify(jwt))
            .contextWrite(ctx -> ctx.put(JwksClientReactorContext.class, context))
            .toFuture();
    }

    private static SignedJWT signedJwt(RSAKey key) {
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
                new JWTClaimsSet.Builder().subject("sherlock").build());
            jwt.sign(new RSASSASigner(key));
            return jwt;
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static RSAKey generateKey(String kid) {
        try {
            return new RSAKeyGenerator(2048).keyID(kid).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Serves a fixed cached JWK Set and counts refreshes, which never replace it: what the fetcher caches is covered by the fetcher tests.
     */
    private static final class StubJwkSetFetcher implements JwkSetFetcher<JWKSet> {
        private final JWKSet cached;
        private final AtomicReference<Mono<JWKSet>> refresh = new AtomicReference<>(Mono.empty());
        private final AtomicInteger refreshes = new AtomicInteger();
        private final AtomicInteger cacheClears = new AtomicInteger();

        private StubJwkSetFetcher(JWKSet cached) {
            this.cached = cached;
        }

        @Override
        @NonNull
        public Publisher<JWKSet> fetch(@Nullable String providerName, @Nullable String url) {
            return Mono.just(cached);
        }

        @Override
        @NonNull
        public Publisher<JWKSet> refresh(@Nullable String providerName, @NonNull String url) {
            refreshes.incrementAndGet();
            return refresh.get();
        }

        @Override
        public void clearCache(String url) {
            cacheClears.incrementAndGet();
        }
    }
}
