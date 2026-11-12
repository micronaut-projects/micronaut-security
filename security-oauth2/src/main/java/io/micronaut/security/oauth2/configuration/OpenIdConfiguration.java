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
import org.jspecify.annotations.NonNull;
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
     * provider response, by the default {@link io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper}
     * at login or by the {@code UserInfo} endpoint token validator, is qualified with the provider name, as
     * {@code providerName:subject}, instead of being the bare {@code sub} claim. The {@code sub} claim is only unique
     * within one provider, so an unqualified username lets a user at one provider share identity with a user at
     * another provider which issued the same {@code sub}.
     *
     * @return {@code true} to always qualify the username, {@code false} to never qualify it, or empty to qualify only when more than one enabled OAuth 2.0 client, other than client-credentials-only clients, is configured under {@code micronaut.security.oauth2.clients}
     * @since 5.5.2
     */
    @NonNull
    default Optional<Boolean> getQualifyUsernameWithProvider() {
        return Optional.empty();
    }

}
