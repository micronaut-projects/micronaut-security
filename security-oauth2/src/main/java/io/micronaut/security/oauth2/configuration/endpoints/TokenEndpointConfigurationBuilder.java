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
import io.micronaut.http.MediaType;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.Objects;
import java.util.Optional;

/**
 * Builder for programmatic {@link TokenEndpointConfiguration} instances.
 *
 * @since 5.1.0
 */
@Experimental
public final class TokenEndpointConfigurationBuilder {

    private @Nullable String url;
    private @Nullable String authenticationMethod;
    private MediaType contentType = MediaType.APPLICATION_FORM_URLENCODED_TYPE;

    /**
     * Sets the token endpoint URL.
     *
     * @param url The token endpoint URL.
     * @return This builder.
     */
    @NonNull
    public TokenEndpointConfigurationBuilder url(@NonNull String url) {
        this.url = Objects.requireNonNull(url, "url");
        return this;
    }

    /**
     * Sets the token endpoint authentication method.
     *
     * @param authenticationMethod The token endpoint authentication method.
     * @return This builder.
     */
    @NonNull
    public TokenEndpointConfigurationBuilder authenticationMethod(@Nullable String authenticationMethod) {
        this.authenticationMethod = authenticationMethod;
        return this;
    }

    /**
     * Sets the token endpoint request content type.
     *
     * @param contentType The token endpoint request content type.
     * @return This builder.
     */
    @NonNull
    public TokenEndpointConfigurationBuilder contentType(@NonNull MediaType contentType) {
        this.contentType = Objects.requireNonNull(contentType, "contentType");
        return this;
    }

    /**
     * Builds the token endpoint configuration.
     *
     * @return The token endpoint configuration.
     */
    @NonNull
    public TokenEndpointConfiguration build() {
        return new BuiltTokenEndpointConfiguration(this);
    }

    private static final class BuiltTokenEndpointConfiguration implements TokenEndpointConfiguration {
        private final @Nullable String url;
        private final @Nullable String authenticationMethod;
        private final MediaType contentType;

        private BuiltTokenEndpointConfiguration(TokenEndpointConfigurationBuilder builder) {
            this.url = builder.url;
            this.authenticationMethod = builder.authenticationMethod;
            this.contentType = builder.contentType;
        }

        @Override
        public Optional<String> getUrl() {
            return Optional.ofNullable(url);
        }

        @Override
        public Optional<String> getAuthenticationMethod() {
            return Optional.ofNullable(authenticationMethod);
        }

        @Override
        @NonNull
        public MediaType getContentType() {
            return contentType;
        }
    }
}
