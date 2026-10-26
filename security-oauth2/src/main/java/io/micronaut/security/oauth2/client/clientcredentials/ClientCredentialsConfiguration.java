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
package io.micronaut.security.oauth2.client.clientcredentials;

import org.jspecify.annotations.NonNull;
import io.micronaut.core.util.Toggleable;
import io.micronaut.http.util.OutgoingRequestProcessorMatcher;
import io.micronaut.security.oauth2.client.clientcredentials.propagation.ClientCredentialsHeaderTokenPropagatorConfiguration;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;

/**
 * Client credentials configuration.
 *
 * @author Sergio del Amo
 * @since 2.2.0
 */
public interface ClientCredentialsConfiguration extends Toggleable, OutgoingRequestProcessorMatcher {

    /**
     * The default expiration applied to an access token whose token response does not include {@code expires_in}
     * and whose access token is not a JWT with an {@code exp} claim.
     * @since 5.4.0
     */
    Duration DEFAULT_EXPIRATION = Duration.ofMinutes(5);

    /**
     *
     * @return Scope to be requested in the client credentials request.
     */
    @NonNull
    Optional<String> getScope();

    /**
     *
     * @return The amount of time for a token obtained via client credentials grant to
     * be considered expired prior to its expiration date.
     */
    @NonNull
    Duration getAdvancedExpiration();

    /**
     *
     * @return The amount of time a token obtained via client credentials grant is cached when the token response does not
     * include {@code expires_in} and the access token is not a JWT with an {@code exp} claim.
     * @since 5.4.0
     */
    @NonNull
    default Duration getDefaultExpiration() {
        return DEFAULT_EXPIRATION;
    }

    @NonNull
    Optional<ClientCredentialsHeaderTokenPropagatorConfiguration> getHeaderPropagation();

    @NonNull
    Map<String, String> getAdditionalRequestParams();

    /**
     * @return A new client credentials configuration builder.
     * @since 5.1.0
     */
    @NonNull
    static ClientCredentialsConfigurationBuilder builder() {
        return new ClientCredentialsConfigurationBuilder();
    }
}
