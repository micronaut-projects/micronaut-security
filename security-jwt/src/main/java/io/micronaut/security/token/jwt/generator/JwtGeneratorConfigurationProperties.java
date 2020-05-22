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

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.value.PropertyResolver;
import io.micronaut.security.token.jwt.config.JwtConfigurationProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link JwtGeneratorConfiguration} implementation.
 *
 * @deprecated Use {@link AccessTokenConfigurationProperties} instead.
 * @author Sergio del Amo
 * @since 1.0
 */
@Deprecated
@ConfigurationProperties(JwtGeneratorConfigurationProperties.PREFIX)
public class JwtGeneratorConfigurationProperties implements JwtGeneratorConfiguration {
    private static final Logger LOG = LoggerFactory.getLogger(JwtGeneratorConfigurationProperties.class);

    public static final String PREFIX = JwtConfigurationProperties.PREFIX + ".generator";

    private final AccessTokenConfigurationProperties accessTokenConfiguration;
    private final PropertyResolver propertyResolver;

    /**
     *
     * @param accessTokenConfiguration Access Token configuration
     * @param propertyResolver Property Resolver
     */
    public JwtGeneratorConfigurationProperties(AccessTokenConfigurationProperties accessTokenConfiguration,
                                               PropertyResolver propertyResolver) {
        this.accessTokenConfiguration = accessTokenConfiguration;
        this.propertyResolver = propertyResolver;
    }

    @Override
    @Deprecated
    public Integer getRefreshTokenExpiration() {
        return null;
    }

    @Deprecated
    @Override
    public Integer getAccessTokenExpiration() {
        return this.accessTokenConfiguration.getExpiration();
    }

    /**
     * deprecated Use micronaut.security.token.jwt.generator.access-token.expiration instead.
     * @param accessTokenExpiration The expiration
     */
    @Deprecated
    public void setAccessTokenExpiration(Integer accessTokenExpiration) {
        if (!propertyResolver.containsProperty(AccessTokenConfigurationProperties.PREFIX + ".expiration")) {
            this.accessTokenConfiguration.setExpiration(accessTokenExpiration);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("ignoring property {} because property {} was set", JwtGeneratorConfigurationProperties.PREFIX + ".access-token-expiration", AccessTokenConfigurationProperties.PREFIX + ".expiration");
            }
        }
    }
}
