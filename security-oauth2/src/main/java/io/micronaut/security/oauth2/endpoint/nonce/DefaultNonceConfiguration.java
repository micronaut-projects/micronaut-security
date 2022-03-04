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
package io.micronaut.security.oauth2.endpoint.nonce;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties.OpenIdConfigurationProperties;
import io.micronaut.security.oauth2.endpoint.AbstractPersistableConfigurationProperties;

/**
 * Configuration properties implementation of nonce validation configuration.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@ConfigurationProperties(DefaultNonceConfiguration.PREFIX)
public class DefaultNonceConfiguration extends AbstractPersistableConfigurationProperties implements NonceConfiguration {

    public static final String PREFIX = OpenIdConfigurationProperties.PREFIX + ".nonce";
    public static final String PERSISTENCE_COOKIE = "cookie";
    public static final String PERSISTENCE_SESSION = "session";
    public static final String DEFAULT_PERSISTENCE = PERSISTENCE_COOKIE;

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;

    protected String persistence = DEFAULT_PERSISTENCE;
    protected boolean enabled = DEFAULT_ENABLED;

    /**
     * Sets the mechanism to persist the nonce for later retrieval for validation.
     * Supported values ({@value #PERSISTENCE_SESSION}, {@value #PERSISTENCE_COOKIE}). Default value ({@value #PERSISTENCE_COOKIE}).
     *
     * @param persistence The persistence mechanism
     */
    public void setPersistence(String persistence) {
        this.persistence = persistence;
    }

    /**
     * Sets whether a nonce parameter will be sent. Default ({@value #DEFAULT_ENABLED}).
     *
     * @param enabled The enabled flag
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
