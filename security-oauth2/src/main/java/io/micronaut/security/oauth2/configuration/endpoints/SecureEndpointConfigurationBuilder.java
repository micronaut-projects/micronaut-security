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
 * Builder for programmatic {@link SecureEndpointConfiguration} instances.
 *
 * @since 5.1.0
 */
@Experimental
public final class SecureEndpointConfigurationBuilder {

    private @Nullable String url;
    private @Nullable String authenticationMethod;

    /**
     * Sets the endpoint URL.
     *
     * @param url The endpoint URL.
     * @return This builder.
     */
    @NonNull
    public SecureEndpointConfigurationBuilder url(@NonNull String url) {
        this.url = Objects.requireNonNull(url, "url");
        return this;
    }

    /**
     * Sets the endpoint authentication method.
     *
     * @param authenticationMethod The endpoint authentication method.
     * @return This builder.
     */
    @NonNull
    public SecureEndpointConfigurationBuilder authenticationMethod(@Nullable String authenticationMethod) {
        this.authenticationMethod = authenticationMethod;
        return this;
    }

    /**
     * Builds the secure endpoint configuration.
     *
     * @return The secure endpoint configuration.
     */
    @NonNull
    public SecureEndpointConfiguration build() {
        return new BuiltSecureEndpointConfiguration(this);
    }

    private static final class BuiltSecureEndpointConfiguration implements SecureEndpointConfiguration {
        private final @Nullable String url;
        private final @Nullable String authenticationMethod;

        private BuiltSecureEndpointConfiguration(SecureEndpointConfigurationBuilder builder) {
            this.url = builder.url;
            this.authenticationMethod = builder.authenticationMethod;
        }

        @Override
        public Optional<String> getUrl() {
            return Optional.ofNullable(url);
        }

        @Override
        public Optional<String> getAuthenticationMethod() {
            return Optional.ofNullable(authenticationMethod);
        }
    }
}
