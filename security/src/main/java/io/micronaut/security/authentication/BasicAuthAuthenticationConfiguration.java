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

    /**
     * The default enable value.
     */
    public static final boolean DEFAULT_ENABLED = true;

    private boolean enabled = DEFAULT_ENABLED;

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

}
