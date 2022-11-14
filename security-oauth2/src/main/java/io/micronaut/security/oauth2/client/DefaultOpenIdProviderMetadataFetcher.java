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
package io.micronaut.security.oauth2.client;

import io.micronaut.context.exceptions.BeanInstantiationException;
import io.micronaut.core.annotation.Blocking;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.optim.StaticOptimizations;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Default implementation of {@link OpenIdProviderMetadataFetcher}.
 *
 * @author Sergio del Amo
 * @since 3.9.0
 */
public class DefaultOpenIdProviderMetadataFetcher implements OpenIdProviderMetadataFetcher {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultOpenIdProviderMetadataFetcher.class);
    private final HttpClient client;
    private final OpenIdClientConfiguration openIdClientConfiguration;
    public static final Optimizations OPTIMIZATIONS = StaticOptimizations.get(Optimizations.class).orElse(new Optimizations(Collections.emptyMap()));

    /**
     * @param openIdClientConfiguration OpenID Client Configuration
     * @param client HTTP Client
     */
    public DefaultOpenIdProviderMetadataFetcher(OpenIdClientConfiguration openIdClientConfiguration,
                                                @Client HttpClient client) {
        this.openIdClientConfiguration = openIdClientConfiguration;
        this.client = client;
    }

    @Override
    @NonNull
    public String getName() {
        return openIdClientConfiguration.getName();
    }

    @Override
    @Blocking
    @NonNull
    public DefaultOpenIdProviderMetadata fetch() {
        return OPTIMIZATIONS.findMetadata(openIdClientConfiguration.getName())
                .map(Supplier::get)
                .orElseGet(fetch(openIdClientConfiguration));
    }

    private Supplier<DefaultOpenIdProviderMetadata> fetch(@NonNull OpenIdClientConfiguration openIdClientConfiguration) {
        return () -> openIdClientConfiguration.getIssuer()
            .map(issuer -> {
                try {
                    URL configurationUrl = new URL(issuer, StringUtils.prependUri(issuer.getPath(), openIdClientConfiguration.getConfigurationPath()));
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Sending request for OpenID configuration for provider [{}] to URL [{}]", openIdClientConfiguration.getName(), configurationUrl);
                    }
                    return client.toBlocking().retrieve(configurationUrl.toString(), DefaultOpenIdProviderMetadata.class);
                } catch (HttpClientResponseException e) {
                    throw new BeanInstantiationException("Failed to retrieve OpenID configuration for " + openIdClientConfiguration.getName(), e);
                } catch (MalformedURLException e) {
                    throw new BeanInstantiationException("Failure parsing issuer URL " + issuer.toString(), e);
                }
            }).orElse(new DefaultOpenIdProviderMetadata());
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
