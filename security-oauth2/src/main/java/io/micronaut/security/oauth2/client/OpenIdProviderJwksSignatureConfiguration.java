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
package io.micronaut.security.oauth2.client;

import com.nimbusds.jose.jwk.KeyType;
import io.micronaut.context.BeanProvider;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfigurationProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.LongSupplier;

/**
 * {@link JwksSignatureConfiguration} backed by the {@code jwks_uri} of an OpenID provider's discovery document.
 * <p>
 * The configuration exists as soon as the OpenID client is configured, even if the discovery document could not
 * be fetched when the application started. That way the application always has a signature configuration, so
 * unsigned tokens are never accepted, while signed tokens are rejected until the provider metadata becomes available.
 * <p>
 * The provider metadata is memoized. If it was already created when this configuration is built, it is used at once.
 * Otherwise it is never resolved on a calling thread, since resolving it fetches the discovery document with a
 * blocking HTTP client and callers verify tokens on request threads: a single resolution is scheduled on the
 * I/O executor when the configuration is built, and again, at most once per failure back-off, when a caller
 * finds the metadata missing. Callers fail fast meanwhile. This bounds the number of discovery requests an
 * unauthenticated caller can trigger while the provider is down, and never blocks a request thread on the provider.
 * <p>
 * The key set is bound to the issuer of the provider: the issuer asserted by the provider metadata, which
 * {@link OpenIdClientFactory} has already validated against the configured issuer identifier, or, if the metadata
 * asserts none, the configured issuer identifier. While the metadata is not available the configured issuer
 * identifier is used; the url cannot be resolved in that case, so no token is verified with this configuration anyway.
 *
 * @author Sergio del Amo
 * @since 3.11.3
 */
@Internal
final class OpenIdProviderJwksSignatureConfiguration implements JwksSignatureConfiguration {
    private static final Logger LOG = LoggerFactory.getLogger(OpenIdProviderJwksSignatureConfiguration.class);

    /**
     * Longest back-off representable in nanoseconds without risking overflow of the monotonic clock arithmetic.
     */
    private static final long MAX_BACKOFF_NANOS = Long.MAX_VALUE / 2;

    private final String name;
    @Nullable
    private final String configuredIssuer;
    private final BeanProvider<DefaultOpenIdProviderMetadata> metadataProvider;
    private final Executor executor;
    private final long backoffNanos;
    private final LongSupplier nanoClock;
    private final AtomicBoolean refreshing = new AtomicBoolean();
    @Nullable
    private volatile DefaultOpenIdProviderMetadata metadata;
    private volatile long nextAttemptNanos;

    /**
     * @param name The OpenID client name
     * @param configuredIssuer The issuer identifier configured for the OpenID client, if any
     * @param resolvedMetadata The provider metadata, if it was already created, so that no resolution is needed
     * @param metadataProvider Provider of the OpenID provider metadata of the client. Only invoked on the executor
     * @param executor Executor used to resolve the metadata, typically the I/O executor
     * @param failureBackoff Minimum time between discovery attempts after a failure. A zero or negative duration disables the back-off: a resolution is then scheduled on every call, at most one at a time
     */
    OpenIdProviderJwksSignatureConfiguration(@NonNull String name,
                                             @Nullable String configuredIssuer,
                                             @Nullable DefaultOpenIdProviderMetadata resolvedMetadata,
                                             @NonNull BeanProvider<DefaultOpenIdProviderMetadata> metadataProvider,
                                             @NonNull Executor executor,
                                             @NonNull Duration failureBackoff) {
        this(name, configuredIssuer, resolvedMetadata, metadataProvider, executor, failureBackoff, System::nanoTime);
    }

    OpenIdProviderJwksSignatureConfiguration(@NonNull String name,
                                             @Nullable String configuredIssuer,
                                             @Nullable DefaultOpenIdProviderMetadata resolvedMetadata,
                                             @NonNull BeanProvider<DefaultOpenIdProviderMetadata> metadataProvider,
                                             @NonNull Executor executor,
                                             @NonNull Duration failureBackoff,
                                             @NonNull LongSupplier nanoClock) {
        this.name = name;
        this.configuredIssuer = configuredIssuer;
        this.metadataProvider = metadataProvider;
        this.executor = executor;
        this.backoffNanos = toNanosSaturated(failureBackoff);
        this.nanoClock = nanoClock;
        if (resolvedMetadata != null) {
            store(resolvedMetadata);
        } else {
            scheduleResolution();
        }
    }

    /**
     * @return The name of the OpenID client
     */
    @NonNull
    public String getName() {
        return name;
    }

    /**
     * @return The {@code jwks_uri} of the OpenID provider
     * @throws IllegalStateException if the provider metadata is not available yet or does not expose a {@code jwks_uri}
     */
    @Override
    @NonNull
    public String getUrl() {
        String jwksUri = metadata().getJwksUri();
        if (jwksUri == null) {
            throw new IllegalStateException("OpenID provider [" + name + "] does not expose a jwks_uri");
        }
        return jwksUri;
    }

    /**
     * @return {@code null}: the key type is not constrained, since the provider may sign with any type of key
     */
    @Override
    @Nullable
    public KeyType getKeyType() {
        return null;
    }

    /**
     * The issuer asserted by the provider metadata is the value providers put in the {@code iss} claim, so it is preferred.
     * The configured issuer may be only the discovery URL (e.g. Oracle IDCS), which differs from the {@code iss} claim and
     * is therefore only used if the metadata does not assert an issuer, or while the metadata is not available.
     *
     * @return The issuer asserted by the provider metadata or, if none, the issuer identifier configured for the OpenID client; {@code null} if neither exists
     */
    @Override
    @Nullable
    public String getIssuer() {
        DefaultOpenIdProviderMetadata resolved;
        try {
            resolved = metadata();
        } catch (IllegalStateException e) {
            return configuredIssuer;
        }
        return issuer(resolved);
    }

    @Override
    @NonNull
    public Integer getCacheExpiration() {
        return JwksSignatureConfigurationProperties.DEFAULT_CACHE_EXPIRATION;
    }

    @Nullable
    private String issuer(@NonNull OpenIdProviderMetadata providerMetadata) {
        String asserted = providerMetadata.getIssuer();
        if (asserted != null && !asserted.trim().isEmpty()) {
            return asserted;
        }
        return configuredIssuer;
    }

    /**
     * @return The provider metadata
     * @throws IllegalStateException if the metadata is not available yet. A resolution is scheduled on the executor if none is in flight and the back-off elapsed
     */
    @NonNull
    private DefaultOpenIdProviderMetadata metadata() {
        DefaultOpenIdProviderMetadata resolved = metadata;
        if (resolved != null) {
            return resolved;
        }
        if (nanoClock.getAsLong() - nextAttemptNanos >= 0) {
            scheduleResolution();
        }
        throw new IllegalStateException(unavailableMessage("it has not been resolved yet"));
    }

    private void store(@NonNull DefaultOpenIdProviderMetadata resolved) {
        metadata = resolved;
        if (issuer(resolved) == null && LOG.isWarnEnabled()) {
            LOG.warn("The JWKS of the OpenID client [{}] is not bound to an issuer because neither 'openid.issuer' is configured nor the provider metadata asserts one. Tokens signed with its keys are accepted whatever their 'iss' claim. Set 'micronaut.security.oauth2.clients.{}.openid.issuer', in particular when several providers are trusted.", name, name);
        }
    }

    private void scheduleResolution() {
        if (!refreshing.compareAndSet(false, true)) {
            return;
        }
        nextAttemptNanos = nanoClock.getAsLong() + backoffNanos;
        try {
            executor.execute(this::resolve);
        } catch (RejectedExecutionException e) {
            refreshing.set(false);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Could not schedule the resolution of the OpenID provider [{}] metadata", name, e);
            }
        }
    }

    private void resolve() {
        try {
            store(metadataProvider.get());
            if (LOG.isInfoEnabled()) {
                LOG.info("Resolved the metadata of OpenID provider [{}]", name);
            }
        } catch (RuntimeException e) {
            nextAttemptNanos = nanoClock.getAsLong() + backoffNanos;
            if (LOG.isDebugEnabled()) {
                LOG.debug(unavailableMessage(e.getMessage()), e);
            }
        } finally {
            refreshing.set(false);
        }
    }

    @NonNull
    private String unavailableMessage(@Nullable String reason) {
        return "Metadata of OpenID provider [" + name + "] is not available: " + reason;
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
}
