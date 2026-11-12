/*
 * Copyright 2017-2023 original authors
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

import com.nimbusds.jose.jwk.JWKSet;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.core.optim.StaticOptimizations;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * Default implementation of {@link JwkSetFetcher} for {@link JWKSet}.
 * @author Sergio del Amo
 * @since 3.9.0
 */
@Singleton
public class DefaultJwkSetFetcher implements JwkSetFetcher<JWKSet> {
    public static final Optimizations OPTIMIZATIONS = StaticOptimizations.get(Optimizations.class).orElse(new Optimizations(Collections.emptyMap()));

    private static final Logger LOG = LoggerFactory.getLogger(DefaultJwkSetFetcher.class);

    /**
     * Longest back-off representable in nanoseconds without risking overflow of the monotonic clock arithmetic.
     */
    private static final long MAX_BACKOFF_NANOS = Long.MAX_VALUE / 2;

    private final JwksClient jwksClient;
    private final Optimizations optimizations;
    private final Duration failureBackoff;
    private final long failureBackoffNanos;
    @Nullable
    private final Duration retrievalTimeout;
    private final LongSupplier nanoTime;
    /**
     * Provider name and JWKS url to the monotonic time (see {@link System#nanoTime()}) at which the JWK Set may be requested again.
     * Keyed like {@link #inFlight}, since the provider selects the {@link JwksClient} settings and two providers sharing a url may fail independently.
     */
    private final Map<FetchKey, Long> failures = new ConcurrentHashMap<>();
    private final Map<FetchKey, Mono<JWKSet>> inFlight = new ConcurrentHashMap<>();

    /**
     * @param jwksClient JWKS Client
     * @deprecated Use {@link #DefaultJwkSetFetcher(JwksClient, JwksClientConfiguration)} instead.
     */
    @Deprecated(forRemoval = true, since = "5.5.2")
    public DefaultJwkSetFetcher(JwksClient jwksClient) {
        this(jwksClient, new JwksClientConfigurationProperties());
    }

    /**
     * @param jwksClient JWKS Client
     * @param optimizations AOT optimizations used as an initial seed for the JWKS of each url.
     * @since 5.4.0
     */
    protected DefaultJwkSetFetcher(JwksClient jwksClient, Optimizations optimizations) {
        this(jwksClient, new JwksClientConfigurationProperties(), System::nanoTime, optimizations);
    }

    /**
     * @param jwksClient JWKS Client
     * @param jwksClientConfiguration JWKS Client Configuration
     * @since 5.5.2
     */
    @Inject
    public DefaultJwkSetFetcher(JwksClient jwksClient, JwksClientConfiguration jwksClientConfiguration) {
        this(jwksClient, jwksClientConfiguration, System::nanoTime);
    }

    /**
     * Constructor with an explicit monotonic clock, for tests.
     * @param jwksClient JWKS Client
     * @param jwksClientConfiguration JWKS Client Configuration
     * @param nanoTime Monotonic clock in nanoseconds, see {@link System#nanoTime()}
     */
    DefaultJwkSetFetcher(JwksClient jwksClient, JwksClientConfiguration jwksClientConfiguration, LongSupplier nanoTime) {
        this(jwksClient, jwksClientConfiguration, nanoTime, OPTIMIZATIONS);
    }

    private DefaultJwkSetFetcher(JwksClient jwksClient, JwksClientConfiguration jwksClientConfiguration, LongSupplier nanoTime, Optimizations optimizations) {
        this.jwksClient = jwksClient;
        this.optimizations = optimizations;
        this.failureBackoff = jwksClientConfiguration.getFailureBackoff();
        this.failureBackoffNanos = toNanosSaturated(failureBackoff);
        Duration timeout = jwksClientConfiguration.getRetrievalTimeout();
        this.retrievalTimeout = timeout.isZero() || timeout.isNegative() ? null : timeout;
        this.nanoTime = nanoTime;
    }

    @Override
    @NonNull
    @SingleResult
    public Publisher<JWKSet> fetch(@Nullable String providerName, @Nullable String url) {
        if (url == null) {
            return Mono.empty();
        }
        Optional<Publisher<JWKSet>> optionalJWKSetPublisher = optimizations.findJwkSet(url)
                .map(Supplier::get)
                .map(Mono::just);
        return optionalJWKSetPublisher.orElseGet(() -> load(providerName, url));
    }

    /**
     * Clears the cache for the given url, including the failure back-off of every provider using it, so that the JWK Set is requested again on the next fetch.
     * If a JWKS was baked at build time for the url, it is discarded and the next call to {@link #fetch(String, String)} loads the JWKS over the network.
     * @param url The Jwks uri
     */
    @Override
    public void clearCache(@NonNull String url) {
        optimizations.clear(url);
        failures.keySet().removeIf(key -> url.equals(key.url()));
    }

    /**
     * Loads the JWK Set unless a previous retrieval for the provider and url failed less than the configured back-off ago.
     * <p>
     * Concurrent callers for the same provider and url share one retrieval. The shared retrieval is deliberately not cancelled when
     * the callers cancel (for example because another signature configuration verified the token first): it runs to completion and a
     * failure is recorded whether or not a caller is still listening. Otherwise a caller able to cancel the verification could trigger
     * one outbound request to a failing JWKS endpoint per request, which is what the back-off prevents.
     * </p>
     * @param providerName The provider name
     * @param url The Jwks uri
     * @return The JWK Set, or empty if it cannot be retrieved, cannot be parsed, contains no keys or the url is backing off.
     */
    @NonNull
    @SingleResult
    private Publisher<JWKSet> load(@Nullable String providerName, @NonNull String url) {
        return Mono.defer(() -> {
            FetchKey key = new FetchKey(providerName, url);
            if (isBackingOff(key)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Skipping JWK Set retrieval from {} for provider {}: a previous retrieval failed less than {} ago", url, providerName, failureBackoff);
                }
                return Mono.empty();
            }
            return inFlight.computeIfAbsent(key, k -> retrieve(k)
                    .doFinally(signal -> inFlight.remove(k))
                    .cache());
        });
    }

    /**
     * Retrieves the JWK Set and records the outcome for the back-off: a success clears it, a failure of any kind starts it.
     * @param key The provider name and Jwks uri
     * @return The JWK Set, or empty if the retrieval fails (including a {@link JwksClient} which throws instead of returning a publisher or does not complete within the retrieval timeout), the response cannot be parsed or the JWK Set contains no keys.
     */
    @NonNull
    private Mono<JWKSet> retrieve(@NonNull FetchKey key) {
        String url = key.url();
        // defer so that an exception thrown by the client itself is handled, and recorded, like an error signal
        Mono<String> content = Mono.defer(() -> Mono.from(jwksClient.load(key.providerName(), url)));
        if (retrievalTimeout != null) {
            // the retrieval is shared by every caller for this provider and url: a client which never completes must not block them forever
            content = content.timeout(retrievalTimeout);
        }
        return content
            .mapNotNull(jwkSetContent -> parse(jwkSetContent, url))
            .filter(jwkSet -> {
                if (jwkSet.isEmpty()) {
                    if (LOG.isWarnEnabled()) {
                        LOG.warn("JWK Set retrieved from {} contains no keys", url);
                    }
                    return false;
                }
                return true;
            })
            .onErrorResume(e -> {
                // The fetcher contract is "empty on failure"
                if (LOG.isWarnEnabled()) {
                    LOG.warn("Failed to retrieve JWK Set from {}: {}", url, e.toString());
                }
                return Mono.empty();
            })
            .doOnNext(jwkSet -> failures.remove(key))
            .switchIfEmpty(Mono.fromRunnable(() -> recordFailure(key)));
    }

    @Nullable
    private static JWKSet parse(@NonNull String jwkSetContent, @NonNull String url) {
        try {
            return JWKSet.parse(jwkSetContent);
        } catch (ParseException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("Exception parsing JWK Set response from " + url, e);
            }
        }
        return null;
    }

    private boolean isBackingOff(@NonNull FetchKey key) {
        Long retryAt = failures.get(key);
        return retryAt != null && nanoTime.getAsLong() - retryAt < 0;
    }

    private void recordFailure(@NonNull FetchKey key) {
        if (failureBackoffNanos <= 0) {
            return;
        }
        failures.put(key, nanoTime.getAsLong() + failureBackoffNanos);
    }

    private static long toNanosSaturated(@NonNull Duration duration) {
        if (duration.isNegative() || duration.isZero()) {
            return 0;
        }
        if (duration.getSeconds() >= TimeUnit.NANOSECONDS.toSeconds(MAX_BACKOFF_NANOS)) {
            return MAX_BACKOFF_NANOS;
        }
        return duration.toNanos();
    }

    /**
     * Identity of a retrieval: the provider selects the {@link JwksClient} settings, so the same url may behave differently per provider.
     * @param providerName The provider name
     * @param url The Jwks uri
     */
    private record FetchKey(@Nullable String providerName, @NonNull String url) {
    }

    /**
     * AOT Optimizations. The JWKS baked at build time is only an initial seed: once {@link #clear(String)} is invoked for a url,
     * {@link #findJwkSet(String)} returns an empty optional for that url and the JWKS is fetched over the network.
     */
    public static class Optimizations {
        private final Map<String, Supplier<JWKSet>> suppliers;
        private final Set<String> consumed = ConcurrentHashMap.newKeySet();

        /**
         *
         * @param suppliers Map with key being the Jwks uri and value the Json Web Key Set.
         */
        public Optimizations(@NonNull Map<String, Supplier<JWKSet>> suppliers) {
            this.suppliers = suppliers;
        }

        /**
         *
         * @param url Json Web Key Set Url
         * @return a Json Web Key  supplier or an empty optional if not cached or if the seed for the url was cleared
         */
        public Optional<Supplier<JWKSet>> findJwkSet(@NonNull String url) {
            if (consumed.contains(url)) {
                return Optional.empty();
            }
            return Optional.ofNullable(suppliers.get(url));
        }

        /**
         * Marks the build-time seed for the url as consumed so that subsequent calls to {@link #findJwkSet(String)} return an empty optional.
         * @param url Json Web Key Set Url
         */
        public void clear(@NonNull String url) {
            if (suppliers.containsKey(url)) {
                consumed.add(url);
            }
        }
    }
}
