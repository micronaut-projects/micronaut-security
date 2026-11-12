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
package io.micronaut.security.scim.server.configuration;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.annotation.Experimental;

/**
 * Configuration for the SCIM HTTP server endpoints.
 *
 * @since 5.4.0
 */
@ConfigurationProperties(ScimServerConfiguration.PREFIX)
@Experimental
public class ScimServerConfiguration {
    /** Configuration prefix. */
    public static final String PREFIX = "micronaut.security.scim";
    /** Default RFC 7644 versioned base path. */
    public static final String DEFAULT_PATH = "/scim/v2";
    /** Default maximum page size applied when a request does not specify {@code count}. */
    public static final int DEFAULT_PAGE_SIZE = 100;

    private boolean enabled = true;
    private String path = DEFAULT_PATH;
    private int defaultPageSize = DEFAULT_PAGE_SIZE;
    private int maxPageSize = 1000;

    /**
     * @return Whether the SCIM endpoints are enabled
     * @since 5.4.0
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * @param enabled Whether the SCIM endpoints are enabled
     * @since 5.4.0
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * @return The base path containing the SCIM protocol version
     * @since 5.4.0
     */
    public String getPath() {
        return path;
    }

    /**
     * @param path The base path containing the SCIM protocol version
     * @since 5.4.0
     */
    public void setPath(String path) {
        this.path = path;
    }

    /**
     * @return The page size used when {@code count} is omitted
     * @since 5.4.0
     */
    public int getDefaultPageSize() {
        return defaultPageSize;
    }

    /**
     * @param defaultPageSize The page size used when {@code count} is omitted
     * @since 5.4.0
     */
    public void setDefaultPageSize(int defaultPageSize) {
        if (defaultPageSize < 0) {
            throw new IllegalArgumentException("defaultPageSize must not be negative");
        }
        this.defaultPageSize = defaultPageSize;
    }

    /**
     * @return The maximum count accepted from a client
     * @since 5.4.0
     */
    public int getMaxPageSize() {
        return maxPageSize;
    }

    /**
     * @param maxPageSize The maximum count accepted from a client
     * @since 5.4.0
     */
    public void setMaxPageSize(int maxPageSize) {
        if (maxPageSize < 0) {
            throw new IllegalArgumentException("maxPageSize must not be negative");
        }
        this.maxPageSize = maxPageSize;
    }
}
