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

import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import jakarta.inject.Singleton;

/**
 * @author Sergio del Amo
 * @since 3.9.0
 */
@Factory
@Internal
@Requires(classes = HttpClient.class)
public class OpenIdProviderMetadataFetcherFactory {
    /**
     * Retrieves OpenID configuration from the provided issuer.
     *
     * @param openIdClientConfiguration The openid client configuration
     * @param issuerClient The client to request the metadata
     * @return The OpenID Provider Metadata Fetcher
     */
    @EachBean(OpenIdClientConfiguration.class)
    @Singleton
    @NonNull
    public OpenIdProviderMetadataFetcher createOpenIdProviderMetadataFetcher(@Parameter OpenIdClientConfiguration openIdClientConfiguration,
                                                                             @Client HttpClient issuerClient) {
        return new DefaultOpenIdProviderMetadataFetcher(openIdClientConfiguration, issuerClient);
    }
}
