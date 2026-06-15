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
package io.micronaut.security.oauth2.configuration.endpoints;

import io.micronaut.core.annotation.Experimental;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.Objects;
import java.util.Optional;

/**
 * Builder for programmatic {@link OauthAuthorizationEndpointConfiguration} instances.
 *
 * @since 5.1.0
 */
@Experimental
public final class OauthAuthorizationEndpointConfigurationBuilder {

    private @Nullable String url;
    private @Nullable String codeChallengeMethod;

    /**
     * Sets the authorization endpoint URL.
     *
     * @param url The authorization endpoint URL.
     * @return This builder.
     */
    @NonNull
    public OauthAuthorizationEndpointConfigurationBuilder url(@NonNull String url) {
        this.url = Objects.requireNonNull(url, "url");
        return this;
    }

    /**
     * Sets the PKCE code challenge method.
     *
     * @param codeChallengeMethod The PKCE code challenge method.
     * @return This builder.
     */
    @NonNull
    public OauthAuthorizationEndpointConfigurationBuilder codeChallengeMethod(@Nullable String codeChallengeMethod) {
        this.codeChallengeMethod = codeChallengeMethod;
        return this;
    }

    /**
     * Builds the OAuth authorization endpoint configuration.
     *
     * @return The OAuth authorization endpoint configuration.
     */
    @NonNull
    public OauthAuthorizationEndpointConfiguration build() {
        return new BuiltOauthAuthorizationEndpointConfiguration(this);
    }

    private static final class BuiltOauthAuthorizationEndpointConfiguration implements OauthAuthorizationEndpointConfiguration {
        private final @Nullable String url;
        private final @Nullable String codeChallengeMethod;

        private BuiltOauthAuthorizationEndpointConfiguration(OauthAuthorizationEndpointConfigurationBuilder builder) {
            this.url = builder.url;
            this.codeChallengeMethod = builder.codeChallengeMethod;
        }

        @Override
        public Optional<String> getUrl() {
            return Optional.ofNullable(url);
        }

        @Override
        @NonNull
        public Optional<String> getCodeChallengeMethod() {
            return Optional.ofNullable(codeChallengeMethod);
        }
    }
}
