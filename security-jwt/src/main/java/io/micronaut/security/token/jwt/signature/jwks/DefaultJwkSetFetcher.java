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
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
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
    private final Optimizations optimizations;

    public DefaultJwkSetFetcher(JwksClient jwksClient) {
        this(jwksClient, OPTIMIZATIONS);
    }

    /**
     * @param jwksClient JWKS Client
     * @param optimizations AOT optimizations used as an initial seed for the JWKS of each url.
     * @since 5.4.0
     */
    protected DefaultJwkSetFetcher(JwksClient jwksClient, Optimizations optimizations) {
        this.jwksClient = jwksClient;
        this.optimizations = optimizations;
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
     * Clears the cache for the given url. If a JWKS was baked at build time for the url, it is discarded and the next call to {@link #fetch(String, String)} loads the JWKS over the network.
     * @param url The Jwks uri
     */
    @Override
    public void clearCache(@NonNull String url) {
        optimizations.clear(url);
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
