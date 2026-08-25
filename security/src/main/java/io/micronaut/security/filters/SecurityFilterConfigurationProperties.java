/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.filters;

import io.micronaut.context.annotation.ConfigurationProperties;
import org.jspecify.annotations.NonNull;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.config.SecurityConfigurationProperties;
import jakarta.validation.constraints.NotBlank;

/**
 * {@link ConfigurationProperties} implementation of {@link SecurityFilterConfiguration}.
 *
 * @author Sergio del Amo
 * @since 3.1.0
 */

@ConfigurationProperties(SecurityFilterConfigurationProperties.PREFIX)
public class SecurityFilterConfigurationProperties implements SecurityFilterConfiguration {
    public static final String PREFIX = SecurityConfigurationProperties.PREFIX + ".filter";
    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;

    /**
     * The default static resource authentication bypass enable value.
     */
    public static final boolean DEFAULT_STATIC_RESOURCE_AUTHENTICATION_BYPASS = false;

    /**
     *
     * The pattern the {@link SecurityFilter} should match.
     */
    @NonNull
    @NotBlank
    private String pattern = "/**";

    private boolean enabled = DEFAULT_ENABLED;

    private boolean staticResourceAuthenticationBypass = DEFAULT_STATIC_RESOURCE_AUTHENTICATION_BYPASS;

    /**
     * @return true if you want to enable the {@link SecurityFilter}
     */
    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    @Override
    public boolean isStaticResourceAuthenticationBypass() {
        return staticResourceAuthenticationBypass;
    }

    @Override
    @NonNull
    public String getPattern() {
        return this.pattern;
    }

    /**
     * Enables {@link SecurityFilter}. Default value {@value #DEFAULT_ENABLED}
     * @param enabled True if it is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Enables bypassing authentication resolution for anonymous static resources.
     * Default value {@value #DEFAULT_STATIC_RESOURCE_AUTHENTICATION_BYPASS}.
     *
     * @param staticResourceAuthenticationBypass Whether the bypass is enabled
     * @since 5.3.3
     */
    public void setStaticResourceAuthenticationBypass(boolean staticResourceAuthenticationBypass) {
        this.staticResourceAuthenticationBypass = staticResourceAuthenticationBypass;
    }

    /**
     * Pattern the {@link SecurityFilter} should match. Default value `/**`. URLS NOT MATCHED BY PREVIOUS PATTERN ARE NOT SECURED
     * @param pattern The pattern
     */
    public void setPath(@NonNull String pattern) {
        if (StringUtils.isNotEmpty(pattern)) {
            this.pattern = pattern;
        }
    }
}
