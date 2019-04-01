/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.configuration;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.config.SecurityConfigurationProperties;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * {@link io.micronaut.context.annotation.ConfigurationProperties} implementation of {@link io.micronaut.security.oauth2.configuration.OauthConfiguration}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Requires(property = OauthConfigurationProperties.PREFIX + ".enabled", value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@Requires(property = OauthConfigurationProperties.PREFIX + ".client-id")
@ConfigurationProperties(OauthConfigurationProperties.PREFIX)
public class OauthConfigurationProperties implements OauthConfiguration {
    public static final String PREFIX = SecurityConfigurationProperties.PREFIX + ".oauth2";

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;

    private String clientId;
    private String clientSecret;
    private boolean enabled = DEFAULT_ENABLED;

    /**
     * OAuth 2.0 Application Client ID.
     * @param clientId The application's Client ID.
     */
    public void setClientId(@Nonnull String clientId) {
        this.clientId = clientId;
    }

    /**
     * OAuth 2.0 Application Client Secret. Optional.
     * @param clientSecret The application's Client Secret.
     */
    public void setClientSecret(@Nullable String clientSecret) {
        this.clientSecret = clientSecret;
    }

    /**
     *
     * @return the application's Client identifier
     */
    @Nonnull
    @Override
    public String getClientId() {
        return clientId;
    }

    /**
     *
     @return the application's Client secret
     */
    @Nullable
    @Override
    public String getClientSecret() {
        return clientSecret;
    }


    /**
     * @return true if you want to enable the {@link OauthConfiguration}
     */
    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    /**
     * Sets whether the {@link OauthConfiguration} is enabled. Default value ({@value #DEFAULT_ENABLED}).
     *
     * @param enabled True if is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

}
