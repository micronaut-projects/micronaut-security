/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.token.jwt.generator;

import edu.umd.cs.findbugs.annotations.NonNull;
import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.util.ArgumentUtils;
import io.micronaut.security.token.jwt.config.JwtConfigurationProperties;

/**
 * Access token configuration.
 *
 * @author James Kleeh
 * @since 2.0.0
 */
@ConfigurationProperties(AccessTokenConfigurationProperties.PREFIX)
public class AccessTokenConfigurationProperties implements AccessTokenConfiguration {

    public static final String PREFIX = JwtConfigurationProperties.PREFIX + ".generator.access-token";

    /**
     * The default expiration.
     */
    @SuppressWarnings("WeakerAccess")
    public static final int DEFAULT_EXPIRATION = 3600;

    @NonNull
    private Integer expiration = DEFAULT_EXPIRATION;

    @Override
    @NonNull
    public Integer getExpiration() {
        return expiration;
    }

    /**
     * Access token expiration. Default value ({@value #DEFAULT_EXPIRATION}).
     * @param expiration The expiration
     */
    public void setExpiration(Integer expiration) {
        ArgumentUtils.requireNonNull("expiration", expiration);
        this.expiration = expiration;
    }

}
