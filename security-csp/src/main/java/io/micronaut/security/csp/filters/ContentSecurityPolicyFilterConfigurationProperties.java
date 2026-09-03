/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.security.csp.filters;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties;
import jakarta.validation.constraints.NotBlank;
import org.jspecify.annotations.NonNull;

/**
 * {@link ConfigurationProperties} implementation of {@link ContentSecurityPolicyFilterConfiguration}.
 *
 * @author Sergio del Amo
 * @since 5.4.0
 */
@ConfigurationProperties(ContentSecurityPolicyFilterConfigurationProperties.PREFIX)
public class ContentSecurityPolicyFilterConfigurationProperties implements ContentSecurityPolicyFilterConfiguration {
    /** Configuration prefix for the CSP response filter. */
    public static final String PREFIX = ContentSecurityPolicyConfigurationProperties.PREFIX + ".filter";
    /** Property that enables or disables the CSP response filter. */
    public static final String PROPERTY_ENABLED = ContentSecurityPolicyFilterConfigurationProperties.PREFIX + ".enabled";
    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;

    /**
     * The pattern the {@link ContentSecurityPolicyFilter} should match.
     */
    @NonNull
    @NotBlank
    private String pattern = "/**";

    private boolean enabled = DEFAULT_ENABLED;

    /** Creates the filter configuration with its default URL pattern. */
    public ContentSecurityPolicyFilterConfigurationProperties() {
    }

    /**
     * Reports whether the CSP response filter is enabled.
     *
     * @return whether the {@link ContentSecurityPolicyFilter} is enabled
     */
    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    @Override
    @NonNull
    public String getPattern() {
        return this.pattern;
    }

    /**
     * Enables or disables the {@link ContentSecurityPolicyFilter}.
     *
     * @param enabled whether the filter is enabled; defaults to {@value #DEFAULT_ENABLED}
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Sets the URL pattern matched by the {@link ContentSecurityPolicyFilter}.
     *
     * <p>Responses for URLs outside this pattern do not receive the module's CSP header.</p>
     *
     * @param pattern the server-filter pattern; defaults to {@code /**}
     */
    public void setPattern(@NonNull String pattern) {
        if (StringUtils.isNotEmpty(pattern)) {
            this.pattern = pattern;
        }
    }
}
