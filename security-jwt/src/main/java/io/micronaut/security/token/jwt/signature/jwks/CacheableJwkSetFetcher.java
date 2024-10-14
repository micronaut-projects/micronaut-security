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
import io.micronaut.cache.annotation.Cacheable;
import io.micronaut.context.annotation.Primary;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;

/**
 * A {@link JwkSetFetcher} that caches the JWKSet using Micronaut Cache with cache named {@value #CACHE_JWKS}.
 *
 * @since 4.11.0
 * @author Sergio del Amo
 */
@Requires(condition = JwksCacheExistsCondition.class)
@Internal
@Primary
@Singleton
@CacheConfig(CacheableJwkSetFetcher.CACHE_JWKS)
public class CacheableJwkSetFetcher extends DefaultJwkSetFetcher {
    public static final String CACHE_JWKS = "jwks";

    public CacheableJwkSetFetcher(JwksClient jwksClient) {
        super(jwksClient);
    }

    @Override
    @Cacheable
    public Publisher<JWKSet> fetch(String providerName, String url) {
        return super.fetch(providerName, url);
    }
}
