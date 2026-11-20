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
import io.micronaut.core.annotation.Internal;
import io.micronaut.http.annotation.ServerFilter;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties;
import jakarta.validation.constraints.NotBlank;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * {@link ConfigurationProperties} implementation of {@link ContentSecurityPolicyFilterConfiguration}.
 *
 * @author Sergio del Amo
 * @since 5.6.0
 */
@ConfigurationProperties(ContentSecurityPolicyFilterConfigurationProperties.PREFIX)
@Internal
final class ContentSecurityPolicyFilterConfigurationProperties implements ContentSecurityPolicyFilterConfiguration {
    /** Configuration prefix for the CSP response filter. */
    public static final String PREFIX = ContentSecurityPolicyConfigurationProperties.PREFIX + ".filter";
    /** Property that enables or disables the CSP response filter. */
    public static final String PROPERTY_ENABLED = ContentSecurityPolicyFilterConfigurationProperties.PREFIX + ".enabled";
    /** Property that sets the {@code Cache-Control} value of HTML responses that carry a nonce. */
    public static final String PROPERTY_NONCE_CACHE_CONTROL = ContentSecurityPolicyFilterConfigurationProperties.PREFIX + ".nonce-cache-control";
    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;
    /**
     * The default {@code Cache-Control} value of HTML responses that carry a nonce.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_NONCE_CACHE_CONTROL = "private";

    /**
     * The pattern the {@link ContentSecurityPolicyNonceFilter} should match.
     */
    @NonNull
    @NotBlank
    private String pattern = ServerFilter.MATCH_ALL_PATTERN;

    private boolean enabled = DEFAULT_ENABLED;

    @Nullable
    private String nonceCacheControl = DEFAULT_NONCE_CACHE_CONTROL;

    /**
     * Reports whether the CSP response filter is enabled.
     *
     * @return whether the {@link ContentSecurityPolicyNonceFilter} is enabled
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

    @Override
    @Nullable
    public String getNonceCacheControl() {
        return this.nonceCacheControl;
    }

    /**
     * Cache-Control value written to HTML responses of requests that received a nonce, for example
     * private or no-store. A Cache-Control header set by the application is kept. Set it to an empty
     * string to not write the header. Default: private.
     *
     * @param nonceCacheControl the {@code Cache-Control} value, or a blank value to not write the
     * header; defaults to {@value #DEFAULT_NONCE_CACHE_CONTROL}
     */
    public void setNonceCacheControl(@Nullable String nonceCacheControl) {
        this.nonceCacheControl = nonceCacheControl;
    }

    /**
     * Whether the CSP response header and the request nonce are generated. Default: true.
     *
     * @param enabled whether the filter is enabled; defaults to {@value #DEFAULT_ENABLED}
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Request path pattern that receives the CSP response header and nonce. Default: /**.
     *
     * @param pattern the server-filter pattern; defaults to {@code /**}
     */
    public void setPattern(@NonNull String pattern) {
        this.pattern = pattern;
    }
}
