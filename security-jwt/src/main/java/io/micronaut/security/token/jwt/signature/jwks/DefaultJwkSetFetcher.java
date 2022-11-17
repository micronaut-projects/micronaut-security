/*
 * Copyright 2017-2021 original authors
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
import io.micronaut.core.annotation.Blocking;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.optim.StaticOptimizations;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;
import java.text.ParseException;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
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

    private final Map<String, JWKSet> jsonWebKeySetsByUrl = new ConcurrentHashMap<>();

    @Override
    @NonNull
    @Blocking
    public Optional<JWKSet> fetch(@Nullable String url) {
        if (url == null) {
            return Optional.empty();
        }
        return OPTIMIZATIONS.findJwkSet(url)
                .map(s -> Optional.of(s.get()))
                .orElseGet(() -> Optional.ofNullable(jsonWebKeySetsByUrl.computeIfAbsent(url, s -> load(url))));
    }

    @Override
    public void clearCache(@NonNull String url) {
        OPTIMIZATIONS.clear(url);
        jsonWebKeySetsByUrl.remove(url);
    }

    @Nullable
    private JWKSet load(@NonNull String url) {
        try {
            return JWKSet.load(new URL(url));
        } catch (IOException | ParseException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("Exception loading JWK from " + url, e);
            }
        }
        return null;
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
