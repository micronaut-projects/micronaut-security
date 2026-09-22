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
package io.micronaut.security.oauth2.client;

import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.Blocking;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonBlocking;
import io.micronaut.core.optim.StaticOptimizations;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.Duration;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

/**
 * Default implementation of {@link OpenIdProviderMetadataFetcher}.
 * <p>
 * The metadata is memoized: once a fetch succeeds, the same {@link DefaultOpenIdProviderMetadata} is returned for the lifetime of the fetcher.
 * When a fetch fails (for example because the provider is temporarily unreachable) the failure is remembered and rethrown for
 * {@link #RETRY_BACKOFF} so that the provider is not hammered; after the back-off elapses the next call to {@link #fetch()} retries.
 * </p>
 * <p>
 * The OpenID configuration is retrieved with a blocking HTTP call, which must not run on an event-loop thread. When {@link #fetch()} is
 * invoked from a non-blocking thread before the metadata is available, and a blocking executor was supplied, the fetch is scheduled on that
 * executor and the call fails fast; the metadata is available to subsequent calls once the background fetch succeeds.
 * </p>
 * <p>
 * When the client configuration declares an issuer and {@link OpenIdClientConfiguration#isValidateIssuer()} is {@code true}, the {@code issuer}
 * of the discovery document must match the configured issuer, ignoring a trailing slash and the case of the scheme, as required by
 * <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation">OpenID Connect Discovery 1.0, Section 4.3</a>.
 * </p>
 *
 * @author Sergio del Amo
 * @since 3.9.0
 */
public class DefaultOpenIdProviderMetadataFetcher implements OpenIdProviderMetadataFetcher {
    public static final Optimizations OPTIMIZATIONS = StaticOptimizations.get(Optimizations.class).orElse(new Optimizations(Collections.emptyMap()));

    /**
     * Minimum time between two fetch attempts after a failed fetch.
     * @since 5.4.0
     */
    public static final Duration RETRY_BACKOFF = Duration.ofSeconds(5);

    private static final Logger LOG = LoggerFactory.getLogger(DefaultOpenIdProviderMetadataFetcher.class);
    private final HttpClient client;
    private final OpenIdClientConfiguration openIdClientConfiguration;
    private final long retryBackoffNanos;
    @Nullable
    private final ExecutorService blockingExecutor;
    private final Object lock = new Object();
    private final AtomicBoolean backgroundFetchInFlight = new AtomicBoolean();

    @Nullable
    private volatile DefaultOpenIdProviderMetadata metadata;

    @Nullable
    private volatile RuntimeException lastFailure;
    private volatile long lastFailureNanos;

    /**
     * @param openIdClientConfiguration OpenID Client Configuration
     * @param client HTTP Client
     */
    public DefaultOpenIdProviderMetadataFetcher(OpenIdClientConfiguration openIdClientConfiguration,
                                                @Client HttpClient client) {
        this(openIdClientConfiguration, client, RETRY_BACKOFF, null);
    }

    /**
     * @param openIdClientConfiguration OpenID Client Configuration
     * @param client HTTP Client
     * @param retryBackoff Minimum time between two fetch attempts after a failed fetch
     * @param blockingExecutor Executor used to fetch the metadata when {@link #fetch()} is invoked from a non-blocking thread. If {@code null}, such invocations fail without scheduling a fetch.
     * @since 5.4.0
     */
    public DefaultOpenIdProviderMetadataFetcher(OpenIdClientConfiguration openIdClientConfiguration,
                                                HttpClient client,
                                                Duration retryBackoff,
                                                @Nullable ExecutorService blockingExecutor) {
        this.openIdClientConfiguration = openIdClientConfiguration;
        this.client = client;
        this.retryBackoffNanos = retryBackoff.toNanos();
        this.blockingExecutor = blockingExecutor;
    }

    @Override
    @NonNull
    public String getName() {
        return openIdClientConfiguration.getName();
    }

    /**
     * Returns the memoized metadata, fetching it if it has not been fetched successfully yet.
     * <p>
     * Within {@link #RETRY_BACKOFF} of a failed attempt the exception of that attempt is rethrown without contacting the provider again.
     * From a non-blocking thread the fetch is scheduled on the blocking executor and an {@link IllegalStateException} is thrown.
     * </p>
     * @return OpenID Provider Metadata
     * @throws ConfigurationException if the issuer URL cannot be parsed or the issuer returned by the provider does not match the configured one
     * @throws IllegalStateException if invoked from a non-blocking thread while the metadata is not available yet
     * @throws RuntimeException if the OpenID configuration could not be retrieved (typically a {@link io.micronaut.http.client.exceptions.HttpClientException})
     */
    @Override
    @Blocking
    @NonNull
    public DefaultOpenIdProviderMetadata fetch() {
        DefaultOpenIdProviderMetadata cached = metadata;
        if (cached != null) {
            return cached;
        }
        if (blockingExecutor != null && isNonBlockingThread()) {
            return fetchFromNonBlockingThread();
        }
        return fetchBlocking();
    }

    @NonNull
    private DefaultOpenIdProviderMetadata fetchBlocking() {
        synchronized (lock) {
            DefaultOpenIdProviderMetadata cached = metadata;
            if (cached != null) {
                return cached;
            }
            RuntimeException failure = lastFailure;
            if (failure != null && withinBackoff()) {
                throw failure;
            }
            try {
                DefaultOpenIdProviderMetadata result = OPTIMIZATIONS.findMetadata(openIdClientConfiguration.getName())
                    .map(Supplier::get)
                    .orElseGet(this::fetchFromIssuer);
                validateIssuer(result);
                metadata = result;
                lastFailure = null;
                return result;
            } catch (RuntimeException e) {
                lastFailureNanos = System.nanoTime();
                lastFailure = e;
                throw e;
            }
        }
    }

    @NonNull
    private DefaultOpenIdProviderMetadata fetchFromNonBlockingThread() {
        RuntimeException failure = lastFailure;
        if (failure != null && withinBackoff()) {
            throw failure;
        }
        scheduleBackgroundFetch();
        throw new IllegalStateException("The OpenID provider metadata of provider [" + openIdClientConfiguration.getName()
            + "] is not available yet. It is being fetched in the background because it cannot be fetched from the non-blocking thread ["
            + Thread.currentThread().getName() + "]." + (failure == null ? "" : " Last failure: " + failure.getMessage()), failure);
    }

    private void scheduleBackgroundFetch() {
        if (!backgroundFetchInFlight.compareAndSet(false, true)) {
            return;
        }
        try {
            blockingExecutor.execute(() -> {
                try {
                    fetchBlocking();
                } catch (RuntimeException e) {
                    // already logged and remembered by fetchBlocking
                } finally {
                    backgroundFetchInFlight.set(false);
                }
            });
        } catch (RuntimeException e) {
            backgroundFetchInFlight.set(false);
            throw e;
        }
    }

    private boolean withinBackoff() {
        return (System.nanoTime() - lastFailureNanos) < retryBackoffNanos;
    }

    private static boolean isNonBlockingThread() {
        Thread thread = Thread.currentThread();
        return thread instanceof NonBlocking || thread instanceof reactor.core.scheduler.NonBlocking;
    }

    @NonNull
    private DefaultOpenIdProviderMetadata fetchFromIssuer() {
        Optional<URL> issuer = openIdClientConfiguration.getIssuer();
        if (issuer.isEmpty()) {
            return new DefaultOpenIdProviderMetadata(openIdClientConfiguration.getName());
        }
        DefaultOpenIdProviderMetadata result = fetch(issuer.get());
        result.setName(openIdClientConfiguration.getName());
        return result;
    }

    @NonNull
    private DefaultOpenIdProviderMetadata fetch(@NonNull URL issuer) {
        URL configurationUrl;
        try {
            configurationUrl = new URL(issuer, StringUtils.prependUri(issuer.getPath(), openIdClientConfiguration.getConfigurationPath()));
        } catch (MalformedURLException e) {
            throw new ConfigurationException("Failure parsing the OpenID configuration URL of provider [" + openIdClientConfiguration.getName() + "] from issuer [" + issuer + "]: " + e.getMessage(), e);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Sending request for OpenID configuration for provider [{}] to URL [{}] running in thread {}", openIdClientConfiguration.getName(), configurationUrl, Thread.currentThread().getName());
        }
        try {
            return client.toBlocking().retrieve(configurationUrl.toString(), DefaultOpenIdProviderMetadata.class);
        } catch (RuntimeException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("Failed to retrieve the OpenID configuration of provider [{}] from [{}]: {}", openIdClientConfiguration.getName(), configurationUrl, e.getMessage(), e);
            }
            throw e;
        }
    }

    private void validateIssuer(@NonNull DefaultOpenIdProviderMetadata result) {
        if (!openIdClientConfiguration.isValidateIssuer()) {
            return;
        }
        Optional<URL> configuredIssuer = openIdClientConfiguration.getIssuer();
        if (configuredIssuer.isEmpty()) {
            return;
        }
        String expected = configuredIssuer.get().toString();
        String discovered = result.getIssuer();
        if (discovered == null || !normalizeIssuer(discovered).equals(normalizeIssuer(expected))) {
            throw new ConfigurationException("The issuer [" + discovered + "] returned by the OpenID configuration of provider [" + openIdClientConfiguration.getName()
                + "] does not match the configured issuer [" + expected + "]. OpenID Connect Discovery 1.0 requires both values to be identical. "
                + "Fix the issuer configuration, or set micronaut.security.oauth2.clients." + openIdClientConfiguration.getName() + ".openid.validate-issuer to false to skip this validation.");
        }
    }

    /**
     * Normalizes an issuer for comparison: trailing slashes are removed and the scheme is lower-cased. Nothing else is altered.
     * @param issuer The issuer
     * @return The normalized issuer
     */
    @Internal
    @NonNull
    static String normalizeIssuer(@NonNull String issuer) {
        String result = issuer.trim();
        while (result.endsWith("/")) {
            result = result.substring(0, result.length() - 1);
        }
        int schemeSeparator = result.indexOf("://");
        if (schemeSeparator > 0) {
            result = result.substring(0, schemeSeparator).toLowerCase(Locale.ROOT) + result.substring(schemeSeparator);
        }
        return result;
    }

    /**
     * AOT Optimizations.
     */
    public static class Optimizations {
        private final Map<String, Supplier<DefaultOpenIdProviderMetadata>> suppliers;

        /**
         * @param suppliers Map with key being the OpenID Name qualifier and
         */
        public Optimizations(Map<String, Supplier<DefaultOpenIdProviderMetadata>> suppliers) {
            this.suppliers = suppliers;
        }

        /**
         * @param name name qualifier
         * @return {@link DefaultOpenIdProviderMetadata} supplier or empty optional if not found for the given name qualifier.
         */
        public Optional<Supplier<DefaultOpenIdProviderMetadata>> findMetadata(String name) {
            return Optional.ofNullable(suppliers.get(name));
        }
    }
}
