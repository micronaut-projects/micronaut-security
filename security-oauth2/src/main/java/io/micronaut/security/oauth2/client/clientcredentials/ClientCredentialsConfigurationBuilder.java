/*
 * Copyright 2017-2026 original authors
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

import io.micronaut.core.annotation.Experimental;
import io.micronaut.security.oauth2.client.clientcredentials.propagation.ClientCredentialsHeaderTokenPropagatorConfiguration;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Builder for programmatic {@link ClientCredentialsConfiguration} instances.
 *
 * @since 5.1.0
 */
@Experimental
public final class ClientCredentialsConfigurationBuilder {

    private boolean enabled = true;
    private @Nullable String scope;
    private Duration advancedExpiration = OauthClientConfiguration.DEFAULT_ADVANCED_EXPIRATION;
    private @Nullable ClientCredentialsHeaderTokenPropagatorConfiguration headerPropagation;
    private Map<String, String> additionalRequestParams = Collections.emptyMap();
    private @Nullable String serviceIdRegex;
    private @Nullable String uriRegex;

    /**
     * Sets whether the client credentials configuration is enabled.
     *
     * @param enabled Whether the client credentials configuration is enabled.
     * @return This builder.
     */
    @NonNull
    public ClientCredentialsConfigurationBuilder enabled(boolean enabled) {
        this.enabled = enabled;
        return this;
    }

    /**
     * Sets the scope requested in the client credentials request.
     *
     * @param scope The client credentials scope.
     * @return This builder.
     */
    @NonNull
    public ClientCredentialsConfigurationBuilder scope(@Nullable String scope) {
        this.scope = scope;
        return this;
    }

    /**
     * Sets the duration before token expiry to consider the token expired.
     *
     * @param advancedExpiration The advanced expiration duration.
     * @return This builder.
     */
    @NonNull
    public ClientCredentialsConfigurationBuilder advancedExpiration(@NonNull Duration advancedExpiration) {
        this.advancedExpiration = Objects.requireNonNull(advancedExpiration, "advancedExpiration");
        return this;
    }

    /**
     * Sets the HTTP header token propagation configuration.
     *
     * @param headerPropagation The HTTP header token propagation configuration.
     * @return This builder.
     */
    @NonNull
    public ClientCredentialsConfigurationBuilder headerPropagation(@Nullable ClientCredentialsHeaderTokenPropagatorConfiguration headerPropagation) {
        this.headerPropagation = headerPropagation;
        return this;
    }

    /**
     * Sets additional parameters included in the client credentials token request.
     *
     * @param additionalRequestParams Additional request parameters.
     * @return This builder.
     */
    @NonNull
    public ClientCredentialsConfigurationBuilder additionalRequestParams(@NonNull Map<String, String> additionalRequestParams) {
        this.additionalRequestParams = Map.copyOf(Objects.requireNonNull(additionalRequestParams, "additionalRequestParams"));
        return this;
    }

    /**
     * Sets the service ID regular expression used to match outgoing requests.
     *
     * @param serviceIdRegex The service ID regular expression.
     * @return This builder.
     */
    @NonNull
    public ClientCredentialsConfigurationBuilder serviceIdRegex(@Nullable String serviceIdRegex) {
        this.serviceIdRegex = serviceIdRegex;
        return this;
    }

    /**
     * Sets the URI regular expression used to match outgoing requests.
     *
     * @param uriRegex The URI regular expression.
     * @return This builder.
     */
    @NonNull
    public ClientCredentialsConfigurationBuilder uriRegex(@Nullable String uriRegex) {
        this.uriRegex = uriRegex;
        return this;
    }

    /**
     * Builds the client credentials configuration.
     *
     * @return The client credentials configuration.
     */
    @NonNull
    public ClientCredentialsConfiguration build() {
        return new DefaultClientCredentialsConfiguration(this);
    }

    private static final class DefaultClientCredentialsConfiguration implements ClientCredentialsConfiguration {
        private final boolean enabled;
        private final @Nullable String scope;
        private final Duration advancedExpiration;
        private final @Nullable ClientCredentialsHeaderTokenPropagatorConfiguration headerPropagation;
        private final Map<String, String> additionalRequestParams;
        private final @Nullable Pattern serviceIdPattern;
        private final @Nullable Pattern uriPattern;

        private DefaultClientCredentialsConfiguration(ClientCredentialsConfigurationBuilder builder) {
            this.enabled = builder.enabled;
            this.scope = builder.scope;
            this.advancedExpiration = builder.advancedExpiration;
            this.headerPropagation = builder.headerPropagation;
            this.additionalRequestParams = Map.copyOf(builder.additionalRequestParams);
            this.serviceIdPattern = builder.serviceIdRegex == null ? null : Pattern.compile(builder.serviceIdRegex);
            this.uriPattern = builder.uriRegex == null ? null : Pattern.compile(builder.uriRegex);
        }

        @Override
        public boolean isEnabled() {
            return enabled;
        }

        @Override
        @NonNull
        public Optional<String> getScope() {
            return Optional.ofNullable(scope);
        }

        @Override
        @NonNull
        public Duration getAdvancedExpiration() {
            return advancedExpiration;
        }

        @Override
        @NonNull
        public Optional<ClientCredentialsHeaderTokenPropagatorConfiguration> getHeaderPropagation() {
            return Optional.ofNullable(headerPropagation);
        }

        @Override
        @NonNull
        public Map<String, String> getAdditionalRequestParams() {
            return additionalRequestParams;
        }

        @Override
        @Nullable
        public Pattern getServiceIdPattern() {
            return serviceIdPattern;
        }

        @Override
        @Nullable
        public Pattern getUriPattern() {
            return uriPattern;
        }
    }
}
