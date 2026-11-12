package io.micronaut.security.token.jwt.signature.jwks;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.Disposable;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultJwkSetFetcherFailureBackoffTest {

    private static final String URL = "http://localhost/keys";
    private static final String PROVIDER = "foo";

    @Test
    void emptyRetrievalIsNotRetriedWhileBackingOff() {
        CountingJwksClient client = new CountingJwksClient(Mono::empty);
        DefaultJwkSetFetcher fetcher = fetcher(client, Duration.ofMinutes(5));
        for (int i = 0; i < 5; i++) {
            assertTrue(fetch(fetcher).isEmpty());
        }
        assertEquals(1, client.invocations.get());
    }

    @Test
    void unparseableRetrievalIsNotRetriedWhileBackingOff() {
        CountingJwksClient client = new CountingJwksClient(() -> Mono.just("<html>not a jwks</html>"));
        DefaultJwkSetFetcher fetcher = fetcher(client, Duration.ofMinutes(5));
        for (int i = 0; i < 5; i++) {
            assertTrue(fetch(fetcher).isEmpty());
        }
        assertEquals(1, client.invocations.get());
    }

    @Test
    void errorYieldsEmptyAndIsNotRetriedWhileBackingOff() {
        CountingJwksClient client = new CountingJwksClient(() -> Mono.error(new IllegalStateException("boom")));
        DefaultJwkSetFetcher fetcher = fetcher(client, Duration.ofMinutes(5));
        for (int i = 0; i < 5; i++) {
            assertTrue(fetch(fetcher).isEmpty());
        }
        assertEquals(1, client.invocations.get());
    }

    @Test
    void clientThrowingSynchronouslyYieldsEmptyAndIsNotRetriedWhileBackingOff() {
        AtomicInteger invocations = new AtomicInteger();
        JwksClient client = (providerName, url) -> {
            invocations.incrementAndGet();
            throw new IllegalStateException("thrown before returning a publisher");
        };
        DefaultJwkSetFetcher fetcher = fetcher(client, Duration.ofMinutes(5));
        for (int i = 0; i < 5; i++) {
            assertTrue(fetch(fetcher).isEmpty());
        }
        assertEquals(1, invocations.get());
    }

    @Test
    void retrievalWhichNeverCompletesTimesOutAndIsNotRetriedWhileBackingOff() {
        AtomicInteger invocations = new AtomicInteger();
        AtomicBoolean cancelled = new AtomicBoolean();
        // a JwksClient without timeouts of its own, stuck on a half-open connection
        JwksClient client = (providerName, url) -> {
            invocations.incrementAndGet();
            return Mono.<String>never().doOnCancel(() -> cancelled.set(true));
        };
        JwksClientConfigurationProperties configuration = new JwksClientConfigurationProperties();
        configuration.setFailureBackoff(Duration.ofMinutes(5));
        configuration.setRetrievalTimeout(Duration.ofMillis(200));
        DefaultJwkSetFetcher fetcher = new DefaultJwkSetFetcher(client, configuration);
        assertTrue(Mono.from(fetcher.fetch(PROVIDER, URL)).block(Duration.ofSeconds(10)) == null);
        assertTrue(cancelled.get(), "the stuck retrieval must be cancelled once it times out");
        // the timeout is a failure: the url is backing off, no new retrieval is started
        for (int i = 0; i < 5; i++) {
            assertTrue(fetch(fetcher).isEmpty());
        }
        assertEquals(1, invocations.get());
    }

    @Test
    void jwksWithoutKeysYieldsEmptyAndIsNotRetriedWhileBackingOff() {
        CountingJwksClient client = new CountingJwksClient(() -> Mono.just("{\"keys\":[]}"));
        DefaultJwkSetFetcher fetcher = fetcher(client, Duration.ofMinutes(5));
        // an empty JWK Set is not emitted, so outer caches (Micronaut Cache, Reactor) do not store it
        for (int i = 0; i < 5; i++) {
            assertTrue(fetch(fetcher).isEmpty());
        }
        assertEquals(1, client.invocations.get());
    }

    @Test
    void successfulRetrievalIsNotSubjectToBackoff() throws Exception {
        String jwks = jwks();
        CountingJwksClient client = new CountingJwksClient(() -> Mono.just(jwks));
        DefaultJwkSetFetcher fetcher = fetcher(client, Duration.ofMinutes(5));
        for (int i = 0; i < 3; i++) {
            Optional<JWKSet> jwkSet = fetch(fetcher);
            assertTrue(jwkSet.isPresent());
            assertFalse(jwkSet.get().isEmpty());
        }
        assertEquals(3, client.invocations.get());
    }

    @Test
    void successfulRetrievalResetsTheBackoff() throws Exception {
        AtomicBoolean failing = new AtomicBoolean(true);
        String jwks = jwks();
        CountingJwksClient client = new CountingJwksClient(() -> failing.get() ? Mono.empty() : Mono.just(jwks));
        FakeClock clock = new FakeClock();
        DefaultJwkSetFetcher fetcher = fetcher(client, Duration.ofSeconds(10), clock);
        assertTrue(fetch(fetcher).isEmpty());
        failing.set(false);
        assertTrue(fetch(fetcher).isEmpty());
        assertEquals(1, client.invocations.get());
        clock.advance(Duration.ofSeconds(10));
        assertTrue(fetch(fetcher).isPresent());
        assertEquals(2, client.invocations.get());
        // no back-off after a success: a following failure is retrieved immediately
        failing.set(true);
        assertTrue(fetch(fetcher).isEmpty());
        assertEquals(3, client.invocations.get());
    }

    @Test
    void zeroBackoffRetriesEveryTime() {
        CountingJwksClient client = new CountingJwksClient(Mono::empty);
        DefaultJwkSetFetcher fetcher = fetcher(client, Duration.ZERO);
        for (int i = 0; i < 5; i++) {
            assertTrue(fetch(fetcher).isEmpty());
        }
        assertEquals(5, client.invocations.get());
    }

    @Test
    void retrievalIsRetriedOnceTheBackoffElapses() {
        CountingJwksClient client = new CountingJwksClient(Mono::empty);
        FakeClock clock = new FakeClock();
        DefaultJwkSetFetcher fetcher = fetcher(client, Duration.ofSeconds(10), clock);
        assertTrue(fetch(fetcher).isEmpty());
        clock.advance(Duration.ofSeconds(9));
        assertTrue(fetch(fetcher).isEmpty());
        assertEquals(1, client.invocations.get());
        clock.advance(Duration.ofSeconds(1));
        assertTrue(fetch(fetcher).isEmpty());
        assertEquals(2, client.invocations.get());
    }

    @Test
    void backoffSurvivesMonotonicClockWrapAround() {
        CountingJwksClient client = new CountingJwksClient(Mono::empty);
        FakeClock clock = new FakeClock(Long.MAX_VALUE - Duration.ofSeconds(1).toNanos());
        DefaultJwkSetFetcher fetcher = fetcher(client, Duration.ofSeconds(10), clock);
        assertTrue(fetch(fetcher).isEmpty());
        clock.advance(Duration.ofSeconds(5)); // wraps around Long.MAX_VALUE
        assertTrue(fetch(fetcher).isEmpty());
        assertEquals(1, client.invocations.get());
        clock.advance(Duration.ofSeconds(5));
        assertTrue(fetch(fetcher).isEmpty());
        assertEquals(2, client.invocations.get());
    }

    @Test
    void hugeBackoffDoesNotOverflow() {
        CountingJwksClient client = new CountingJwksClient(Mono::empty);
        DefaultJwkSetFetcher fetcher = fetcher(client, Duration.ofDays(365L * 1000));
        assertTrue(fetch(fetcher).isEmpty());
        assertTrue(fetch(fetcher).isEmpty());
        assertEquals(1, client.invocations.get());
    }

    @Test
    void clearCacheResetsTheBackoff() {
        CountingJwksClient client = new CountingJwksClient(Mono::empty);
        DefaultJwkSetFetcher fetcher = fetcher(client, Duration.ofMinutes(5));
        assertTrue(fetch(fetcher).isEmpty());
        assertTrue(fetch(fetcher).isEmpty());
        assertEquals(1, client.invocations.get());
        fetcher.clearCache(URL);
        assertTrue(fetch(fetcher).isEmpty());
        assertEquals(2, client.invocations.get());
    }

    @Test
    void backoffIsKeyedByUrl() {
        CountingJwksClient client = new CountingJwksClient(Mono::empty);
        DefaultJwkSetFetcher fetcher = fetcher(client, Duration.ofMinutes(5));
        assertTrue(fetch(fetcher).isEmpty());
        assertTrue(Mono.from(fetcher.fetch(PROVIDER, "http://localhost/other-keys")).blockOptional().isEmpty());
        assertEquals(2, client.invocations.get());
    }

    @Test
    void backoffIsKeyedByProviderAsWellAsUrl() throws Exception {
        String jwks = jwks();
        List<String> providers = new CopyOnWriteArrayList<>();
        // provider "a" fails (for example a misconfigured service-specific HTTP client) while provider "b" succeeds for the same url
        JwksClient client = (providerName, url) -> {
            providers.add(providerName);
            return "a".equals(providerName) ? Mono.empty() : Mono.just(jwks);
        };
        DefaultJwkSetFetcher fetcher = fetcher(client, Duration.ofMinutes(5));
        assertTrue(Mono.from(fetcher.fetch("a", URL)).blockOptional().isEmpty());
        Optional<JWKSet> b = Mono.from(fetcher.fetch("b", URL)).blockOptional();
        assertTrue(b.isPresent());
        assertFalse(b.get().isEmpty());
        assertEquals(List.of("a", "b"), providers);
        // "a" is still backing off
        assertTrue(Mono.from(fetcher.fetch("a", URL)).blockOptional().isEmpty());
        assertEquals(List.of("a", "b"), providers);
        // clearing the url resets the back-off of every provider
        fetcher.clearCache(URL);
        assertTrue(Mono.from(fetcher.fetch("a", URL)).blockOptional().isEmpty());
        assertEquals(List.of("a", "b", "a"), providers);
    }

    @Test
    void concurrentFetchesShareTheInFlightRetrievalAndFailure() throws Exception {
        AtomicInteger invocations = new AtomicInteger();
        CountDownLatch release = new CountDownLatch(1);
        JwksClient client = (providerName, url) -> Mono.<String>fromCallable(() -> {
            invocations.incrementAndGet();
            release.await(10, TimeUnit.SECONDS);
            throw new IllegalStateException("slow failure");
        }).subscribeOn(Schedulers.boundedElastic());
        DefaultJwkSetFetcher fetcher = fetcher(client, Duration.ofMinutes(5));
        int callers = 10;
        ExecutorService executor = Executors.newFixedThreadPool(callers);
        try {
            List<Future<Optional<JWKSet>>> results = new ArrayList<>();
            for (int i = 0; i < callers; i++) {
                results.add(executor.submit(() -> fetch(fetcher)));
            }
            Thread.sleep(300);
            release.countDown();
            for (Future<Optional<JWKSet>> result : results) {
                assertTrue(result.get(10, TimeUnit.SECONDS).isEmpty());
            }
            assertEquals(1, invocations.get());
            assertTrue(fetch(fetcher).isEmpty());
            assertEquals(1, invocations.get());
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void concurrentFetchesForDifferentProvidersAreNotCoalesced() throws Exception {
        List<String> providers = new CopyOnWriteArrayList<>();
        CountDownLatch release = new CountDownLatch(1);
        JwksClient client = (providerName, url) -> Mono.<String>fromCallable(() -> {
            providers.add(providerName);
            release.await(10, TimeUnit.SECONDS);
            return "{\"keys\":[]}";
        }).subscribeOn(Schedulers.boundedElastic());
        DefaultJwkSetFetcher fetcher = fetcher(client, Duration.ofMinutes(5));
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            // each provider may use its own HTTP client for the same url, so the retrievals are not shared across providers
            Future<Optional<JWKSet>> a = executor.submit(() -> Mono.from(fetcher.fetch("a", URL)).blockOptional());
            Future<Optional<JWKSet>> b = executor.submit(() -> Mono.from(fetcher.fetch("b", URL)).blockOptional());
            Thread.sleep(300);
            release.countDown();
            assertTrue(a.get(10, TimeUnit.SECONDS).isEmpty());
            assertTrue(b.get(10, TimeUnit.SECONDS).isEmpty());
            assertEquals(2, providers.size());
            assertTrue(providers.contains("a"));
            assertTrue(providers.contains("b"));
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void cancelledCallerDoesNotCancelTheRetrievalAndItsFailureIsStillRecorded() throws Exception {
        AtomicInteger invocations = new AtomicInteger();
        AtomicBoolean cancelled = new AtomicBoolean();
        CountDownLatch subscribed = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        JwksClient client = (providerName, url) -> {
            invocations.incrementAndGet();
            return Mono.<String>fromCallable(() -> {
                    release.await(10, TimeUnit.SECONDS);
                    throw new IllegalStateException("slow failure");
                })
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSubscribe(s -> subscribed.countDown())
                .doOnCancel(() -> cancelled.set(true));
        };
        DefaultJwkSetFetcher fetcher = fetcher(client, Duration.ofMinutes(5));
        // a verification cancelled because another signature configuration verified the token first, or an aborted request
        Disposable caller = Mono.from(fetcher.fetch(PROVIDER, URL)).subscribe();
        assertTrue(subscribed.await(10, TimeUnit.SECONDS));
        caller.dispose();
        assertFalse(cancelled.get(), "the shared retrieval must not be cancelled by a caller, otherwise a failing endpoint is never backed off");
        // while the retrieval is in flight, a new caller shares it
        Disposable second = Mono.from(fetcher.fetch(PROVIDER, URL)).subscribe();
        assertEquals(1, invocations.get());
        second.dispose();
        // once it fails, the failure is recorded although nobody observed it: this caller joins the in-flight retrieval and
        // waits for its (empty) outcome, the next one is skipped because of the back-off
        release.countDown();
        assertTrue(fetch(fetcher).isEmpty());
        assertTrue(fetch(fetcher).isEmpty());
        assertEquals(1, invocations.get(), "a cancelled caller must not cause a new retrieval of a failing endpoint");
    }

    private static String jwks() throws Exception {
        return new JWKSet(new RSAKeyGenerator(2048).keyID("test-kid").algorithm(JWSAlgorithm.RS256).generate().toPublicJWK()).toString(true);
    }

    private static Optional<JWKSet> fetch(DefaultJwkSetFetcher fetcher) {
        return Mono.from(fetcher.fetch(PROVIDER, URL)).blockOptional();
    }

    private static DefaultJwkSetFetcher fetcher(JwksClient client, Duration failureBackoff) {
        return new DefaultJwkSetFetcher(client, configuration(failureBackoff));
    }

    private static DefaultJwkSetFetcher fetcher(JwksClient client, Duration failureBackoff, FakeClock clock) {
        return new DefaultJwkSetFetcher(client, configuration(failureBackoff), clock::nanoTime);
    }

    private static JwksClientConfiguration configuration(Duration failureBackoff) {
        JwksClientConfigurationProperties configuration = new JwksClientConfigurationProperties();
        configuration.setFailureBackoff(failureBackoff);
        return configuration;
    }

    private static final class FakeClock {
        private final AtomicLong nanos;

        private FakeClock() {
            this(0L);
        }

        private FakeClock(long nanos) {
            this.nanos = new AtomicLong(nanos);
        }

        long nanoTime() {
            return nanos.get();
        }

        void advance(Duration duration) {
            nanos.addAndGet(duration.toNanos());
        }
    }

    private static final class CountingJwksClient implements JwksClient {
        private final AtomicInteger invocations = new AtomicInteger();
        private final Supplier<Publisher<String>> response;

        private CountingJwksClient(Supplier<Publisher<String>> response) {
            this.response = response;
        }

        @Override
        public Publisher<String> load(String providerName, String url) {
            invocations.incrementAndGet();
            return response.get();
        }
    }
}
