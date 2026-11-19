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
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.annotation.ServerFilter;

/**
 * Binds configuration for the Fetch Metadata request filter.
 *
 * <p>Unlike other configuration properties classes, this one is {@code @Context} and rejects a
 * blank pattern in its setter. The filter reads its pattern from a property placeholder, and a
 * blank pattern would silently stop it from matching any request; failing startup instead keeps
 * the security filter from being disabled by a configuration mistake. The bean only exists
 * while the filter is enabled, so a disabled filter never fails startup.</p>
 *
 * @since 5.6.0
 */
@Requires(property = FetchMetadataFilterConfiguration.PROPERTY_ENABLED, value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@Context
@ConfigurationProperties(FetchMetadataFilterConfiguration.PREFIX)
@Internal
final class FetchMetadataFilterConfigurationProperties implements FetchMetadataFilterConfiguration {
    /** Default filter enablement. */
    public static final boolean DEFAULT_ENABLED = true;
    /** Default server-filter pattern. */
    public static final String DEFAULT_PATTERN = ServerFilter.MATCH_ALL_PATTERN;

    private String pattern = DEFAULT_PATTERN;

    private boolean enabled = DEFAULT_ENABLED;

    /**
     * Reports whether the Fetch Metadata request filter is enabled.
     *
     * @return whether the Fetch Metadata request filter is enabled
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
     */
    public void setPattern(String pattern) {
        if (!StringUtils.hasText(pattern)) {
            throw new ConfigurationException("Property [" + PROPERTY_PATTERN + "] must not be empty or blank. "
                + "Remove it to apply the filter to every path, or set [" + PROPERTY_ENABLED + "] to false to disable the filter.");
        }
        this.pattern = pattern;
    }
}
