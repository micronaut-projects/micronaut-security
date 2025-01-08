/*
 * Copyright 2017-2024 original authors
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
import io.micronaut.context.annotation.Primary;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.async.annotation.SingleResult;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;

/**
 * A {@link JwkSetFetcher} that caches the JWKSet using Reactor {@link Mono#cacheInvalidateIf(Predicate)}.
 *
 * @since 4.11.0
 * @author Sergio del Amo
 * @deprecated It will be removed in a future version. Use {@link CacheableJwkSetFetcher} instead.
 */
@Requires(missingBeans = CacheableJwkSetFetcher.class)
@Internal
@Primary
@Singleton
@Deprecated(forRemoval = true, since = "4.11.0")
final class ReactorCacheJwkSetFetcher extends DefaultJwkSetFetcher {
    private final Map<CacheKey, Mono<JwksCacheEntry>> cache = new ConcurrentHashMap<>();
    private final Map<String, JwksSignatureConfiguration> jwksSignatureConfigurations;

    ReactorCacheJwkSetFetcher(JwksClient jwksClient, Map<String, JwksSignatureConfiguration> jwksSignatureConfigurations) {
        super(jwksClient);
        this.jwksSignatureConfigurations = jwksSignatureConfigurations;
    }

    @Override
    @NonNull
    @SingleResult
    public Publisher<JWKSet> fetch(@Nullable String providerName, @Nullable String url) {
        CacheKey k = new CacheKey(providerName, url);
        return cache.computeIfAbsent(k, this::jwksCacheEntry)
                .map(JwksCacheEntry::jwkSet);
    }

    private Mono<JwksCacheEntry> jwksCacheEntry(CacheKey cacheKey) {
        return Mono.from(super.fetch(cacheKey.providerName, cacheKey.url()))
                .defaultIfEmpty(new JWKSet())
                .map(jwksSet -> instantiateCacheEntry(cacheKey, jwksSet))
                .cacheInvalidateIf(JwksCacheEntry::isExpired);
    }

    private JwksCacheEntry instantiateCacheEntry(CacheKey cacheKey, JWKSet jwkSet) {
        return new JwksCacheEntry(jwkSet, Instant.now().plusSeconds(jwksSignatureConfigurations.get(cacheKey.providerName) != null
                ? jwksSignatureConfigurations.get(cacheKey.providerName).getCacheExpiration()
                : JwksSignatureConfigurationProperties.DEFAULT_CACHE_EXPIRATION));
    }
    
    private record CacheKey(String providerName, String url) {
    }

    private record JwksCacheEntry(JWKSet jwkSet, Instant cacheExpiryAt) {
        private boolean isExpired() {
            return jwkSet.isEmpty() || (cacheExpiryAt != null && Instant.now().isAfter(cacheExpiryAt));
        }
    }
}
