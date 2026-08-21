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
package io.micronaut.security.reporting;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.StringUtils;
import jakarta.validation.constraints.NotBlank;

/**
 * Binds configuration for the Reporting API response filter.
 *
 * @since 5.4.0
 */
@ConfigurationProperties(ReportingEndpointsFilterConfigurationProperties.PREFIX)
@Internal
final class ReportingEndpointsFilterConfigurationProperties implements ReportingEndpointsFilterConfiguration {
    /** Configuration prefix for the Reporting API response filter. */
    public static final String PREFIX = "micronaut.security.reporting.filter";
    /** Property that enables or disables the Reporting API response filter. */
    public static final String PROPERTY_ENABLED = ReportingEndpointsFilterConfigurationProperties.PREFIX + ".enabled";
    /** Default filter enablement. */
    public static final boolean DEFAULT_ENABLED = true;
    /** Default server-filter pattern. */
    public static final String DEFAULT_PATTERN = "/**";

    @NotBlank
    private String pattern = DEFAULT_PATTERN;

    private boolean enabled = DEFAULT_ENABLED;

    /**
     * Reports whether the Reporting API response filter is enabled.
     *
     * @return whether the reporting response filter is enabled
     * @since 5.4.0
     */
    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    @Override
    public String getPattern() {
        return this.pattern;
    }

    /**
     * Enables or disables the reporting response filter.
     *
     * @param enabled whether the filter is enabled; defaults to {@value #DEFAULT_ENABLED}
     * @since 5.4.0
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Sets the request path pattern matched by the reporting response filter.
     *
     * <p>Responses for URLs outside this pattern do not receive the module's
     * {@code Reporting-Endpoints} header.</p>
     *
     * @param pattern the server-filter pattern; defaults to {@value #DEFAULT_PATTERN}
     * @since 5.4.0
     */
    public void setPattern(String pattern) {
        if (StringUtils.isNotEmpty(pattern)) {
            this.pattern = pattern;
        }
    }
}
