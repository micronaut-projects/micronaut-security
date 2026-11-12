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
import io.micronaut.cache.annotation.CacheConfig;
import io.micronaut.cache.annotation.CacheInvalidate;
import io.micronaut.cache.annotation.Cacheable;
import io.micronaut.context.annotation.Primary;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.reactivestreams.Publisher;

/**
 * A {@link JwkSetFetcher} that caches the JWKSet using Micronaut Cache with cache named {@value #CACHE_JWKS}.
 *
 * @since 4.11.0
 * @author Sergio del Amo
 */
@Requires(classes = CacheConfig.class)
@Requires(condition = JwksCacheConfigurationExistsCondition.class)
@Internal
@Primary
@Singleton
@CacheConfig(CacheableJwkSetFetcher.CACHE_JWKS)
class CacheableJwkSetFetcher extends DefaultJwkSetFetcher {
    public static final String CACHE_JWKS = "jwks";

    CacheableJwkSetFetcher(JwksClient jwksClient, JwksClientConfiguration jwksClientConfiguration) {
        super(jwksClient, jwksClientConfiguration);
    }

    @Override
    @Cacheable
    public Publisher<JWKSet> fetch(String providerName, String url) {
        return super.fetch(providerName, url);
    }

    /**
     * Clears the whole {@value #CACHE_JWKS} cache, since cache entries are keyed by provider name and url, together with the failure back-off for the given url.
     * @param url The Jwks uri
     */
    @Override
    @CacheInvalidate(all = true)
    public void clearCache(@NonNull String url) {
        super.clearCache(url);
    }
}
