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
import io.micronaut.cache.annotation.CacheConfig;
import io.micronaut.cache.annotation.Cacheable;
import io.micronaut.core.annotation.Blocking;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.core.optim.StaticOptimizations;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.text.ParseException;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
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

    private final JwksClient jwksClient;

    /**
     * @deprecated Use {@link DefaultJwkSetFetcher(JwksClient)} instead.
     */
    @Deprecated(forRemoval = true, since = "4.5.0")
    public DefaultJwkSetFetcher() {
        this(new ResourceRetrieverJwksClient(Schedulers.boundedElastic()));
    }

    @Inject
    public DefaultJwkSetFetcher(JwksClient jwksClient) {
        this.jwksClient = jwksClient;
    }

    @Override
    @NonNull
    @Blocking
    @Deprecated(forRemoval = true, since = "4.5.0")
    public Optional<JWKSet> fetch(String url) {
        return Mono.from(fetch(null, url)).blockOptional();
    }

    @Override
    @NonNull
    @SingleResult
    public Publisher<JWKSet> fetch(@Nullable String providerName, @Nullable String url) {
        if (url == null) {
            return Mono.empty();
        }
        Optional<Publisher<JWKSet>> optionalJWKSetPublisher = OPTIMIZATIONS.findJwkSet(url)
                .map(Supplier::get)
                .map(Mono::just);
        return optionalJWKSetPublisher.orElseGet(() -> load(providerName, url));
    }

    @Override
    public void clearCache(@NonNull String url) {
        OPTIMIZATIONS.clear(url);
    }

    @Nullable
    @SingleResult
    private Publisher<JWKSet> load(@Nullable String providerName, @NonNull String url) {
        return Mono.from(jwksClient.load(providerName, url))
                .mapNotNull(jwkSetContent -> {
                    try {
                        return JWKSet.parse(jwkSetContent);
                    } catch (ParseException e) {
                        if (LOG.isErrorEnabled()) {
                            LOG.error("Exception parsing JWK Set response from " + url, e);
                        }
                    }
                    return null;
                });
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
