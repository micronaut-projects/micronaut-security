/*
 * Copyright 2017-2025 original authors
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
package io.micronaut.security.oauth2.endpoint.userinfo;

import io.micronaut.core.annotation.Introspected;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.naming.Named;

import java.util.Objects;

/**
 * For each bean of type {@link UserInfoClientTokenValidatorConfiguration} a bean of type {@link UserInfoClientTokenValidator} is instantiated.
 * @param name Name Qualifier
 * @param baseUrl Authorization Server Base URL
 * @param path User Info Endpoint Path
 * @since 4.15.0
 */
@Introspected
public record UserInfoClientTokenValidatorConfiguration(
    @NonNull String baseUrl,
    @NonNull String name,
    @NonNull String path
    ) implements Named {
    public static final String DEFAULT_PATH = "/userinfo";

    public UserInfoClientTokenValidatorConfiguration(String baseUrl, String name) {
        this(baseUrl, name, DEFAULT_PATH);
    }

    @Override
    public @NonNull String getName() {
        return name();
    }

    /**
     * Creates a new builder instance.
     * @return The builder
     */
    @NonNull
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link UserInfoClientTokenValidatorConfiguration}.
     * baseUrl and name are required. path defaults to {@link #DEFAULT_PATH}.
     */
    public static final class Builder {
        private String baseUrl;
        private String name;
        private String path = DEFAULT_PATH;

        /**
         * @param baseUrl Authorization Server Base URL
         * @return this builder
         */
        @NonNull
        public Builder baseUrl(@NonNull String baseUrl) {
            this.baseUrl = baseUrl;
            return this;
        }

        /**
         * @param name Name qualifier
         * @return this builder
         */
        @NonNull
        public Builder name(@NonNull String name) {
            this.name = name;
            return this;
        }

        /**
         * @param path User info endpoint path (defaults to {@link #DEFAULT_PATH})
         * @return this builder
         */
        @NonNull
        public Builder path(@NonNull String path) {
            this.path = path;
            return this;
        }

        /**
         * Builds the configuration instance.
         * @return The UserInfoClientConfiguration
         */
        @NonNull
        public UserInfoClientTokenValidatorConfiguration build() {
            Objects.requireNonNull(baseUrl, "baseUrl must be set");
            Objects.requireNonNull(name, "name must be set");
            if (path == null) {
                path = DEFAULT_PATH;
            }
            return new UserInfoClientTokenValidatorConfiguration(baseUrl, name, path);
        }
    }
}
