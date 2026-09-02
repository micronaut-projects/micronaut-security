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
package io.micronaut.security.fetchmetadata;

import io.micronaut.context.annotation.Context;
import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.StringUtils;

/**
 * Binds configuration for the Fetch Metadata request filter.
 *
 * @since 5.4.0
 */
@Context
@ConfigurationProperties(FetchMetadataFilterConfigurationProperties.PREFIX)
@Internal
final class FetchMetadataFilterConfigurationProperties implements FetchMetadataFilterConfiguration {
    /** Configuration prefix for the Fetch Metadata request filter. */
    public static final String PREFIX = "micronaut.security.fetch-metadata.filter";
    /** Property that enables or disables the Fetch Metadata request filter. */
    public static final String PROPERTY_ENABLED = FetchMetadataFilterConfigurationProperties.PREFIX + ".enabled";
    /** Default filter enablement. */
    public static final boolean DEFAULT_ENABLED = true;
    /** Default server-filter pattern. */
    public static final String DEFAULT_PATTERN = "/**";

    private String pattern = DEFAULT_PATTERN;

    private boolean enabled = DEFAULT_ENABLED;

    /**
     * Reports whether the Fetch Metadata request filter is enabled.
     *
     * @return whether the Fetch Metadata request filter is enabled
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
     * Enables or disables the Fetch Metadata request filter.
     *
     * @param enabled whether the filter is enabled; defaults to {@value #DEFAULT_ENABLED}
     * @since 5.4.0
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Sets the request path pattern matched by the Fetch Metadata request filter.
     * Requests outside this pattern are not evaluated by this module.
     *
     * @param pattern the server-filter pattern; defaults to {@value #DEFAULT_PATTERN}
     * @throws ConfigurationException if the pattern is empty or blank
     * @since 5.4.0
     */
    public void setPattern(String pattern) {
        if (!StringUtils.hasText(pattern)) {
            throw new ConfigurationException("Property [" + PREFIX + ".pattern] must not be empty or blank");
        }
        this.pattern = pattern;
    }
}
