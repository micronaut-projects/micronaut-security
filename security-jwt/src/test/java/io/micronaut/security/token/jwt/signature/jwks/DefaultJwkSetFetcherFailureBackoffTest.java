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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A failed JWK Set retrieval must not be retried until the configured back-off elapses.
 */
class DefaultJwkSetFetcherFailureBackoffTest {

    private static final String URL = "http://localhost/keys";
    private static final Duration BACKOFF = Duration.ofSeconds(10);

    @Test
    void emptyRetrievalIsNotRetriedWhileBackingOff() {
        CountingFetcher fetcher = new CountingFetcher(Optional::empty, BACKOFF, new FakeClock());
        for (int i = 0; i < 5; i++) {
            assertFalse(fetcher.fetch(URL).isPresent());
        }
        assertEquals(1, fetcher.retrievals.get());
    }

    @Test
    void retrievalThrowingYieldsEmptyAndIsNotRetriedWhileBackingOff() {
        CountingFetcher fetcher = new CountingFetcher(() -> {
            throw new IllegalStateException("boom");
        }, BACKOFF, new FakeClock());
        for (int i = 0; i < 5; i++) {
            assertFalse(fetcher.fetch(URL).isPresent());
        }
        assertEquals(1, fetcher.retrievals.get());
    }

    @Test
    void jwksWithoutKeysYieldsEmptyAndIsNotRetriedWhileBackingOff() {
        CountingFetcher fetcher = new CountingFetcher(() -> Optional.of(new JWKSet()), BACKOFF, new FakeClock());
        for (int i = 0; i < 5; i++) {
            assertFalse(fetcher.fetch(URL).isPresent());
        }
        assertEquals(1, fetcher.retrievals.get());
    }

    @Test
    void successfulRetrievalIsNotSubjectToBackoff() throws Exception {
        JWKSet jwks = jwks();
        CountingFetcher fetcher = new CountingFetcher(() -> Optional.of(jwks), BACKOFF, new FakeClock());
        for (int i = 0; i < 3; i++) {
            assertTrue(fetcher.fetch(URL).isPresent());
        }
        assertEquals(3, fetcher.retrievals.get());
    }

    @Test
    void successfulRetrievalResetsTheBackoff() throws Exception {
        JWKSet jwks = jwks();
        AtomicBoolean failing = new AtomicBoolean(true);
        FakeClock clock = new FakeClock();
        CountingFetcher fetcher = new CountingFetcher(() -> failing.get() ? Optional.empty() : Optional.of(jwks), BACKOFF, clock);
        assertFalse(fetcher.fetch(URL).isPresent());
        clock.advance(BACKOFF.plusSeconds(1));
        failing.set(false);
        assertTrue(fetcher.fetch(URL).isPresent());
        failing.set(true);
        assertFalse(fetcher.fetch(URL).isPresent());
        assertFalse(fetcher.fetch(URL).isPresent());
        assertEquals(3, fetcher.retrievals.get());
    }

    @Test
    void zeroBackoffRetriesEveryTime() {
        CountingFetcher fetcher = new CountingFetcher(Optional::empty, Duration.ZERO, new FakeClock());
        for (int i = 0; i < 5; i++) {
            assertFalse(fetcher.fetch(URL).isPresent());
        }
        assertEquals(5, fetcher.retrievals.get());
    }

    @Test
    void retrievalIsRetriedOnceTheBackoffElapses() {
        FakeClock clock = new FakeClock();
        CountingFetcher fetcher = new CountingFetcher(Optional::empty, BACKOFF, clock);
        assertFalse(fetcher.fetch(URL).isPresent());
        clock.advance(BACKOFF.minusMillis(1));
        assertFalse(fetcher.fetch(URL).isPresent());
        assertEquals(1, fetcher.retrievals.get());
        clock.advance(Duration.ofMillis(1));
        assertFalse(fetcher.fetch(URL).isPresent());
        assertEquals(2, fetcher.retrievals.get());
    }

    @Test
    void backoffSurvivesMonotonicClockWrapAround() {
        FakeClock clock = new FakeClock(Long.MAX_VALUE - Duration.ofSeconds(1).toNanos());
        CountingFetcher fetcher = new CountingFetcher(Optional::empty, BACKOFF, clock);
        assertFalse(fetcher.fetch(URL).isPresent());
        clock.advance(Duration.ofSeconds(5)); // wraps around to a negative nanoTime
        assertFalse(fetcher.fetch(URL).isPresent());
        assertEquals(1, fetcher.retrievals.get());
        clock.advance(BACKOFF);
        assertFalse(fetcher.fetch(URL).isPresent());
        assertEquals(2, fetcher.retrievals.get());
    }

    @Test
    void hugeBackoffDoesNotOverflow() {
        FakeClock clock = new FakeClock();
        CountingFetcher fetcher = new CountingFetcher(Optional::empty, Duration.ofDays(365 * 1000L), clock);
        assertFalse(fetcher.fetch(URL).isPresent());
        clock.advance(Duration.ofDays(365));
        assertFalse(fetcher.fetch(URL).isPresent());
        assertEquals(1, fetcher.retrievals.get());
    }

    @Test
    void clearCacheResetsTheBackoff() {
        CountingFetcher fetcher = new CountingFetcher(Optional::empty, BACKOFF, new FakeClock());
        assertFalse(fetcher.fetch(URL).isPresent());
        assertFalse(fetcher.fetch(URL).isPresent());
        assertEquals(1, fetcher.retrievals.get());
        fetcher.clearCache(URL);
        assertFalse(fetcher.fetch(URL).isPresent());
        assertEquals(2, fetcher.retrievals.get());
    }

    @Test
    void backoffIsKeyedByUrl() {
        CountingFetcher fetcher = new CountingFetcher(Optional::empty, BACKOFF, new FakeClock());
        assertFalse(fetcher.fetch(URL).isPresent());
        assertFalse(fetcher.fetch("http://localhost/other-keys").isPresent());
        assertFalse(fetcher.fetch(URL).isPresent());
        assertEquals(2, fetcher.retrievals.get());
    }

    @Test
    void nullUrlIsNeverRetrieved() {
        CountingFetcher fetcher = new CountingFetcher(Optional::empty, BACKOFF, new FakeClock());
        assertFalse(fetcher.fetch(null).isPresent());
        assertEquals(0, fetcher.retrievals.get());
    }

    private static JWKSet jwks() throws Exception {
        return new JWKSet(new RSAKeyGenerator(2048).keyID("kid").algorithm(JWSAlgorithm.RS256).generate().toPublicJWK());
    }

    private static JwksClientConfiguration configuration(Duration failureBackoff) {
        JwksClientConfigurationProperties configuration = new JwksClientConfigurationProperties();
        configuration.setFailureBackoff(failureBackoff);
        return configuration;
    }

    static class CountingFetcher extends DefaultJwkSetFetcher {
        final AtomicInteger retrievals = new AtomicInteger();
        private final Supplier<Optional<JWKSet>> retrieval;

        CountingFetcher(Supplier<Optional<JWKSet>> retrieval, Duration failureBackoff, FakeClock clock) {
            super(configuration(failureBackoff), clock::nanoTime);
            this.retrieval = retrieval;
        }

        @Override
        protected Optional<JWKSet> retrieve(String url) {
            retrievals.incrementAndGet();
            return retrieval.get();
        }
    }

    static class FakeClock {
        private final AtomicLong nanos;

        FakeClock() {
            this(0L);
        }

        FakeClock(long start) {
            this.nanos = new AtomicLong(start);
        }

        long nanoTime() {
            return nanos.get();
        }

        void advance(Duration duration) {
            nanos.addAndGet(duration.toNanos());
        }
    }
}
