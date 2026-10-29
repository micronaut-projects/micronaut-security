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
package io.micronaut.security.oauth2.configuration;

import io.micronaut.security.oauth2.configuration.endpoints.EndSessionConfiguration;
import io.micronaut.core.annotation.NonNull;
import java.util.Optional;

/**
 * Configuration for OpenID not specific to a client.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public interface OpenIdConfiguration {

    /**
     * @return the Callback Uri
     */
    String getLogoutUri();

    /**
     * @return Optional end session configuration
     */
    Optional<EndSessionConfiguration> getEndSession();

    /**
     * @return Claims validation configuration
     */
    OpenIdClaimsValidationConfiguration getClaimsValidation();

    /**
     * @return Claims configuration
     */
    OpenIdAdditionalClaimsConfiguration getAdditionalClaims();

    /**
     * Whether the username of an {@link io.micronaut.security.authentication.Authentication} built from an OpenID
     * provider response is qualified with the provider name, as {@code providerName:subject}, so that the same
     * subject at two providers never maps to one user.
     *
     * @return {@code true} to always qualify the username, {@code false} to never qualify it, or empty when not set
     * and the component which creates the authentication applies its own default
     * @since 4.18.2
     */
    @NonNull
    default Optional<Boolean> getQualifyUsernameWithProvider() {
        return Optional.empty();
    }

}
