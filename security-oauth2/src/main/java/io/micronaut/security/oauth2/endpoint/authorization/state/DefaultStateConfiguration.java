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
package io.micronaut.security.oauth2.endpoint.authorization.state;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;
import io.micronaut.security.oauth2.endpoint.authorization.state.validation.StateValidationConfiguration;

import java.util.Optional;

/**
 * Configuration properties implementation of state validation configuration.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@ConfigurationProperties(DefaultStateConfiguration.PREFIX)
public class DefaultStateConfiguration implements StateValidationConfiguration {

    public static final String PREFIX = OauthConfigurationProperties.PREFIX + ".state";

    private static final boolean DEFAULT_ENABLED = true;
    private static final String DEFAULT_PERSISTENCE = "cookie";

    private String persistence = DEFAULT_PERSISTENCE;
    private boolean enabled = DEFAULT_ENABLED;

    @Override
    public Optional<String> getPersistence() {
        return Optional.ofNullable(persistence);
    }

    /**
     * Sets the mechanism to persist the state for later retrieval for validation.
     * Supported values ("session", "cookie"). Default value ({@value #DEFAULT_PERSISTENCE}).
     *
     * @param persistence The persistence mechanism
     */
    public void setPersistence(String persistence) {
        this.persistence = persistence;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether a state parameter will be sent. Default ({@value #DEFAULT_ENABLED}).
     *
     * @param enabled The enabled flag
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
