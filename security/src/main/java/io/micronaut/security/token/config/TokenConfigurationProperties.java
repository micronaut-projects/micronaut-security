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
package io.micronaut.security.token.config;

import edu.umd.cs.findbugs.annotations.NonNull;
import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.config.SecurityConfigurationProperties;

/**
 * Defines Security Token Configuration.
 * @author Sergio del Amo
 * @since 1.0
 */
@ConfigurationProperties(TokenConfigurationProperties.PREFIX)
public class TokenConfigurationProperties implements TokenConfiguration {

    public static final String PREFIX = SecurityConfigurationProperties.PREFIX + ".token";

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;

    private boolean enabled = DEFAULT_ENABLED;

    @NonNull
    private String rolesName = TokenConfiguration.DEFAULT_ROLES_NAME;

    @NonNull
    private String nameKey = TokenConfiguration.DEFAULT_NAME_KEY;

    @Override
    public boolean isEnabled() {
        return enabled;
    }


    /**
     * @see TokenConfiguration#getRolesName() ().
     * If not specified, defaults to {@link #DEFAULT_ROLES_NAME}.
     */
    @Override
    @NonNull
    public String getRolesName() {
        return rolesName;
    }

    /**
     * Sets whether the configuration is enabled. Default value {@value #DEFAULT_ENABLED}.
     *
     * @param enabled True if it is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * {@link io.micronaut.security.authentication.Authentication} attributes map key for the user's roles. Default value {@value io.micronaut.security.token.config.TokenConfiguration#DEFAULT_ROLES_NAME}.
     * @param rolesName The roles name
     */
    public void setRolesName(@NonNull String rolesName) {
        if (StringUtils.isNotEmpty(rolesName)) {
            this.rolesName = rolesName;
        }
    }

    /**
     * @see TokenConfiguration#getNameKey()
     * If not specified, defaults to {@link #DEFAULT_NAME_KEY}.
     */
    @Override
    @NonNull
    public String getNameKey() {
        return nameKey;
    }

    /**
     * {@link io.micronaut.security.authentication.Authentication} attributes map key for the user's name. Default value {@value io.micronaut.security.token.config.TokenConfiguration#DEFAULT_NAME_KEY}.
     * @param nameKey key for name
     */
    public void setNameKey(@NonNull String nameKey) {
        this.nameKey = nameKey;
    }
}
