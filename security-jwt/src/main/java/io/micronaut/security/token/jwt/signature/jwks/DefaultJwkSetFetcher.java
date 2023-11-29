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
import io.micronaut.context.BeanContext;
import io.micronaut.core.annotation.Blocking;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.optim.StaticOptimizations;
import io.micronaut.core.util.SupplierUtil;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.HttpClientConfiguration;
import io.micronaut.http.client.LoadBalancer;
import io.micronaut.http.client.exceptions.HttpClientException;
import io.micronaut.inject.qualifiers.Qualifiers;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.net.URL;
import java.text.ParseException;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
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

    private final BeanContext beanContext;
    private final Supplier<HttpClient> defaultJwkSetClient;
    private final ConcurrentHashMap<String, HttpClient> jwkSetClients = new ConcurrentHashMap<>();

    public DefaultJwkSetFetcher(BeanContext beanContext,
                                HttpClientConfiguration defaultClientConfiguration) {
        this.beanContext = beanContext;
        this.defaultJwkSetClient = SupplierUtil.memoized(() -> beanContext.createBean(HttpClient.class, LoadBalancer.empty(), defaultClientConfiguration));
    }

    @Override
    @NonNull
    @Blocking
    public Optional<JWKSet> fetch(@Nullable String url) {
        if (url == null) {
            return Optional.empty();
        }
        return OPTIMIZATIONS.findJwkSet(url)
            .map(s -> Optional.of(s.get()))
            .orElseGet(() -> Optional.ofNullable(load(url)));
    }

    @Override
    @NonNull
    @Blocking
    public Optional<JWKSet> fetch(@NonNull String providerName, @Nullable String url) {
        if (url == null) {
            return Optional.empty();
        }
        return OPTIMIZATIONS.findJwkSet(url)
                .map(s -> Optional.of(s.get()))
                .orElseGet(() -> Optional.ofNullable(load(providerName, url)));
    }

    @Override
    public void clearCache(@NonNull String url) {
        OPTIMIZATIONS.clear(url);
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

    @Nullable
    private JWKSet load(@NonNull String providerName, @NonNull String url) {
        try {
            String jwkSetContent = Mono.from(getClient(providerName).retrieve(url)).block();
            Objects.requireNonNull(jwkSetContent, "JWK Set must not be null.");
            return JWKSet.parse(jwkSetContent);
        } catch (HttpClientException | ParseException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("Exception loading JWK from " + url, e);
            }
        }
        return null;
    }

    /**
     * Retrieves a client for the given provider.
     *
     * @param providerName The provider name
     * @return An HTTP client to use to send the request
     */
    protected HttpClient getClient(String providerName) {
        return jwkSetClients.computeIfAbsent(providerName, provider -> {
            Optional<io.micronaut.http.client.HttpClient> client = beanContext.findBean(io.micronaut.http.client.HttpClient.class, Qualifiers.byName(provider));
            return client.orElseGet(defaultJwkSetClient);
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
