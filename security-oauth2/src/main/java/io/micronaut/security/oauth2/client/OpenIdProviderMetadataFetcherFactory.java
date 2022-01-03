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

import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.json.JsonMapper;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;

/**
 * @author Sergio del Amo
 * @since 3.3.0
 */
@Factory
@Internal
public class OpenIdProviderMetadataFetcherFactory {
    private final JsonMapper jsonMapper;

    /**
     *
     * @param jsonMapper JSON Mapper.
     */
    public OpenIdProviderMetadataFetcherFactory(JsonMapper jsonMapper) {
        this.jsonMapper = jsonMapper;
    }

    /**
     * Retrieves OpenID configuration from the provided issuer.
     *
     * @param openIdClientConfiguration The openid client configuration
     * @param issuerClient The client to request the metadata
     * @return The OpenID configuration
     */
    @EachBean(OpenIdClientConfiguration.class)
    @NonNull
    public OpenIdProviderMetadataFetcher openIdConfiguration(@Parameter OpenIdClientConfiguration openIdClientConfiguration,
                                                             @Client HttpClient issuerClient) {
        return new DefaultOpenIdProviderMetadataFetcher(openIdClientConfiguration, jsonMapper, issuerClient);
    }
}
