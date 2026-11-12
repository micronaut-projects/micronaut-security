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

import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.DisabledBeanException;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.SupplierUtil;
import org.jspecify.annotations.NonNull;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.HttpClientConfiguration;
import io.micronaut.http.client.LoadBalancer;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.utils.NoRedirectHttpClientConfiguration;
import jakarta.annotation.PreDestroy;
import jakarta.inject.Singleton;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * @author Sergio del Amo
 * @since 3.9.0
 */
@Factory
@Internal
@Requires(classes = HttpClient.class)
@Requires(beans = HttpClientConfiguration.class)
public class OpenIdProviderMetadataFetcherFactory {

    private final Supplier<HttpClient> issuerClient;
    private final AtomicReference<HttpClient> createdClient = new AtomicReference<>();

    /**
     * @param beanContext The bean context
     * @param defaultClientConfiguration The default client configuration. Its settings are copied, but the client created
     *                                   from it never follows redirects.
     * @since 5.5.2
     */
    public OpenIdProviderMetadataFetcherFactory(BeanContext beanContext,
                                                HttpClientConfiguration defaultClientConfiguration) {
        this.issuerClient = SupplierUtil.memoized(() -> {
            HttpClient client = beanContext.createBean(HttpClient.class, LoadBalancer.empty(), new NoRedirectHttpClientConfiguration(defaultClientConfiguration));
            createdClient.set(client);
            return client;
        });
    }

    /**
     * Retrieves OpenID configuration from the provided issuer.
     *
     * @param openIdClientConfiguration The openid client configuration
     * @return The OpenID Provider Metadata Fetcher
     */
    @EachBean(OpenIdClientConfiguration.class)
    @Singleton
    @NonNull
    public OpenIdProviderMetadataFetcher createOpenIdProviderMetadataFetcher(@Parameter OpenIdClientConfiguration openIdClientConfiguration) {
        if (!openIdClientConfiguration.isFetchConfiguration()) {
            throw new DisabledBeanException("OpenID provider metadata fetching is disabled for provider [" +
                openIdClientConfiguration.getName() + "]");
        }
        return new DefaultOpenIdProviderMetadataFetcher(openIdClientConfiguration, issuerClient.get());
    }

    /**
     * Closes the HTTP client this factory created.
     */
    @PreDestroy
    public void close() {
        HttpClient client = createdClient.getAndSet(null);
        if (client != null) {
            client.close();
        }
    }
}
