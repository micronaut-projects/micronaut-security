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

import io.micronaut.core.annotation.Blocking;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.naming.Named;

/**
 * Fetches OpenIdProviderMetadata for a {@link io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration}.
 * @author Sergio del Amo
 * @since 3.7.0
 */
public interface OpenIdProviderMetadataFetcher extends Named {
    /**
     * It fetches Authorization Server OpenID metadata from a remote server.
     * @return OpenID Provider Metadata
     */
    @Blocking
    @NonNull
    DefaultOpenIdProviderMetadata fetch();
}
