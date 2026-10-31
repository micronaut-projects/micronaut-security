/*
 * Copyright 2017-2020 original authors
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
import com.nimbusds.jose.util.DefaultResourceRetriever;
import io.micronaut.core.annotation.Blocking;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.optim.StaticOptimizations;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.ParseException;
import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * Default implementation of {@link JwkSetFetcher} for {@link JWKSet}.
 * <p>
 * A failed retrieval (the endpoint cannot be reached, responds with a non-2xx status, the body cannot be parsed, or the
 * JWK Set contains no keys) is recorded per url and the JWK Set is not requested again until the back-off configured with
 * {@link JwksClientConfiguration#getFailureBackoff()} elapses. Otherwise every bearer string which merely parses as a signed
 * JWT would trigger one outbound request to the failing JWKS endpoint, and one error log entry, while the endpoint is down.
 * The retrieval itself is bounded by {@link JwksClientConfiguration#getRetrievalTimeout()}.
 * <p>
 * The JWK Set is retrieved with the JDK {@link HttpURLConnection} and redirects are never followed: a redirect returned by
 * the JWKS endpoint is a failed retrieval. Otherwise a malicious or compromised provider could make the application fetch
 * any address it can reach and treat the JSON found there as the keys that sign the tokens it accepts.
 *
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

    private final Duration failureBackoff;
    private final long failureBackoffNanos;
    private final int retrievalTimeoutMillis;
    private final LongSupplier nanoTime;
    private final DefaultResourceRetriever resourceRetriever;
    /**
     * JWKS url to the monotonic time (see {@link System#nanoTime()}) at which the JWK Set may be requested again.
     */
    private final Map<String, Long> failures = new ConcurrentHashMap<>();

    /**
     * @deprecated Use {@link #DefaultJwkSetFetcher(JwksClientConfiguration)} instead.
     */
    @Deprecated
    public DefaultJwkSetFetcher() {
        this(new JwksClientConfigurationProperties());
    }

    /**
     * @param jwksClientConfiguration JWKS Client Configuration
     * @since 3.11.3
     */
    @Inject
    public DefaultJwkSetFetcher(JwksClientConfiguration jwksClientConfiguration) {
        this(jwksClientConfiguration, System::nanoTime);
    }

    /**
     * Constructor with an explicit monotonic clock, for tests.
     * @param jwksClientConfiguration JWKS Client Configuration
     * @param nanoTime Monotonic clock in nanoseconds, see {@link System#nanoTime()}
     */
    DefaultJwkSetFetcher(JwksClientConfiguration jwksClientConfiguration, LongSupplier nanoTime) {
        this.failureBackoff = jwksClientConfiguration.getFailureBackoff();
        this.failureBackoffNanos = toNanosSaturated(failureBackoff);
        this.retrievalTimeoutMillis = toMillisSaturated(jwksClientConfiguration.getRetrievalTimeout());
        this.nanoTime = nanoTime;
        this.resourceRetriever = new DefaultResourceRetriever(retrievalTimeoutMillis, retrievalTimeoutMillis, 0) {
            @Override
            protected HttpURLConnection openHTTPConnection(URL url) throws IOException {
                HttpURLConnection connection = super.openHTTPConnection(url);
                // never follow redirects when retrieving the JWK Set of the identity provider
                connection.setInstanceFollowRedirects(false);
                return connection;
            }
        };
    }

    /**
     * Fetches the JWK Set unless a previous retrieval for the url failed less than the configured back-off ago.
     *
     * @param url The Jwks uri
     * @return The JWK Set, or empty if it cannot be retrieved, cannot be parsed, contains no keys or the url is backing off.
     */
    @Override
    @NonNull
    @Blocking
    public Optional<JWKSet> fetch(@Nullable String url) {
        if (url == null) {
            return Optional.empty();
        }
        Optional<Supplier<JWKSet>> optimized = OPTIMIZATIONS.findJwkSet(url);
        if (optimized.isPresent()) {
            return Optional.of(optimized.get().get());
        }
        return load(url);
    }

    /**
     * Clears the cache for the given url, including its failure back-off, so that the JWK Set is requested again on the next fetch.
     * @param url The Jwks uri
     */
    @Override
    public void clearCache(@NonNull String url) {
        OPTIMIZATIONS.clear(url);
        failures.remove(url);
    }

    /**
     * Retrieves the JWK Set from the url without following redirects. Subclasses may override it to change how the JWK Set is
     * retrieved; the failure back-off is applied by {@link #fetch(String)} regardless.
     *
     * @param url The Jwks uri
     * @return The JWK Set, or empty if it cannot be retrieved or parsed
     * @since 3.11.3
     */
    @NonNull
    @Blocking
    protected Optional<JWKSet> retrieve(@NonNull String url) {
        try {
            return Optional.ofNullable(JWKSet.parse(resourceRetriever.retrieveResource(new URL(url)).getContent()));
        } catch (IOException | ParseException e) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("Failed to retrieve JWK Set from {}: {}", url, e.toString());
            }
        }
        return Optional.empty();
    }

    @NonNull
    private Optional<JWKSet> load(@NonNull String url) {
        if (isBackingOff(url)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Skipping JWK Set retrieval from {}: a previous retrieval failed less than {} ago", url, failureBackoff);
            }
            return Optional.empty();
        }
        Optional<JWKSet> jwkSet;
        try {
            jwkSet = retrieve(url);
        } catch (RuntimeException e) {
            // The fetcher contract is "empty on failure"
            if (LOG.isWarnEnabled()) {
                LOG.warn("Failed to retrieve JWK Set from {}: {}", url, e.toString());
            }
            jwkSet = Optional.empty();
        }
        if (jwkSet.isPresent() && jwkSet.get().getKeys().isEmpty()) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("JWK Set retrieved from {} contains no keys", url);
            }
            jwkSet = Optional.empty();
        }
        if (jwkSet.isPresent()) {
            failures.remove(url);
        } else {
            recordFailure(url);
        }
        return jwkSet;
    }

    private boolean isBackingOff(@NonNull String url) {
        Long retryAt = failures.get(url);
        return retryAt != null && nanoTime.getAsLong() - retryAt < 0;
    }

    private void recordFailure(@NonNull String url) {
        if (failureBackoffNanos <= 0) {
            return;
        }
        failures.put(url, nanoTime.getAsLong() + failureBackoffNanos);
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

    private static int toMillisSaturated(@NonNull Duration duration) {
        if (duration.isNegative() || duration.isZero()) {
            return 0;
        }
        if (duration.getSeconds() >= TimeUnit.MILLISECONDS.toSeconds(Integer.MAX_VALUE)) {
            return Integer.MAX_VALUE;
        }
        return (int) duration.toMillis();
    }

    /**
     * AOT Optimizations.
     */
    public static class Optimizations {
        private final Map<String, Supplier<JWKSet>> suppliers;

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
         * @return a Json Web Key  supplier or an empty optional if not cached
         */
        public Optional<Supplier<JWKSet>> findJwkSet(@NonNull String url) {
            return Optional.ofNullable(suppliers.get(url));
        }

        /**
         * @param url Json Web Key Set Url
         */
        public void clear(@NonNull String url) {
            suppliers.remove(url);
        }
    }
}
