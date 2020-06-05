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
package io.micronaut.security.authentication;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.util.Toggleable;
import io.micronaut.security.config.SecurityConfigurationProperties;

/**
 * Configuration for basic authentication.
 *
 * @author James Kleeh
 * @since 2.0.0
 */
@ConfigurationProperties(BasicAuthAuthenticationConfiguration.PREFIX)
public class BasicAuthAuthenticationConfiguration implements Toggleable {

    public static final String PREFIX = SecurityConfigurationProperties.PREFIX + ".basic-auth";

    private static final boolean DEFAULT_ENABLED = true;
    private static final String DEFAULT_ROLES_NAME = "roles";

    private boolean enabled = DEFAULT_ENABLED;
    private String rolesName = DEFAULT_ROLES_NAME;

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Enables the {@link BasicAuthAuthenticationFetcher}. Default value {@value #DEFAULT_ENABLED}.
     *
     * @param enabled True if enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * @return The name in the {@link Authentication} that represents the roles
     */
    public String getRolesName() {
        return rolesName;
    }

    /**
     * @param rolesName The key to store the roles in the {@link Authentication} attributes
     */
    public void setRolesName(String rolesName) {
        this.rolesName = rolesName;
    }
}
