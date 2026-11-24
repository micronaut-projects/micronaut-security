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
package io.micronaut.security.csp.conf;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.annotation.Internal;

/**
 * Binds the {@code micronaut.security.csp} configuration namespace to the default CSP policy.
 *
 * <p>Defaults deny source-list directives unless a directive deliberately needs a narrower
 * application-compatible default, such as {@code form-action 'self'}.</p>
 *
 * <p>Applications should depend on {@link ContentSecurityPolicyConfiguration} rather than this
 * internal binding type when they need to consume CSP settings programmatically.</p>
 */
@ConfigurationProperties(ContentSecurityPolicyConfigurationProperties.PREFIX)
@Internal
public final class ContentSecurityPolicyConfigurationProperties implements ContentSecurityPolicyConfiguration {
    /** Configuration prefix for all CSP settings. */
    public static final String PREFIX = "micronaut.security.csp";
    /** Configuration prefix for the {@code base-uri} directive. */
    public static final String PROPERTY_BASE_URI = ContentSecurityPolicyConfigurationProperties.PREFIX + ".base-uri";
    /** Configuration prefix for the {@code connect-src} directive. */
    public static final String PROPERTY_CONNECT_SRC = ContentSecurityPolicyConfigurationProperties.PREFIX + ".connect-src";
    /** Configuration prefix for the {@code default-src} directive. */
    public static final String PROPERTY_DEFAULT_SRC = ContentSecurityPolicyConfigurationProperties.PREFIX + ".default-src";
    /** Configuration prefix for the {@code fenced-frame-src} directive. */
    public static final String PROPERTY_FENCED_FRAME_SRC = ContentSecurityPolicyConfigurationProperties.PREFIX + ".fenced-frame-src";
    /** Configuration prefix for the {@code font-src} directive. */
    public static final String PROPERTY_FONT_SRC = ContentSecurityPolicyConfigurationProperties.PREFIX + ".font-src";
    /** Configuration prefix for the {@code form-action} directive. */
    public static final String PROPERTY_FORM_ACTION = ContentSecurityPolicyConfigurationProperties.PREFIX + ".form-action";
    /** Configuration prefix for the {@code frame-ancestors} directive. */
    public static final String PROPERTY_FRAME_ANCESTORS = ContentSecurityPolicyConfigurationProperties.PREFIX + ".frame-ancestors";
    /** Configuration prefix for the {@code frame-src} directive. */
    public static final String PROPERTY_FRAME_SRC = ContentSecurityPolicyConfigurationProperties.PREFIX + ".frame-src";
    /** Configuration prefix for the {@code img-src} directive. */
    public static final String PROPERTY_IMG_SRC = ContentSecurityPolicyConfigurationProperties.PREFIX + ".img-src";
    /** Configuration prefix for the {@code manifest-src} directive. */
    public static final String PROPERTY_MANIFEST_SRC = ContentSecurityPolicyConfigurationProperties.PREFIX + ".manifest-src";
    /** Configuration prefix for the {@code media-src} directive. */
    public static final String PROPERTY_MEDIA_SRC = ContentSecurityPolicyConfigurationProperties.PREFIX + ".media-src";
    /** Configuration prefix for the {@code object-src} directive. */
    public static final String PROPERTY_OBJECT_SRC = ContentSecurityPolicyConfigurationProperties.PREFIX + ".object-src";
    /** Configuration prefix for the {@code prefetch-src} directive. */
    public static final String PROPERTY_PREFETCH_SRC = ContentSecurityPolicyConfigurationProperties.PREFIX + ".prefetch-src";
    /** Configuration prefix for the deprecated {@code report-uri} directive. */
    public static final String PROPERTY_REPORT_URI = ContentSecurityPolicyConfigurationProperties.PREFIX + ".report-uri";
    /** Configuration prefix for the {@code require-trusted-types-for} directive. */
    public static final String PROPERTY_REQUIRE_TRUSTED_TYPES_FOR = ContentSecurityPolicyConfigurationProperties.PREFIX + ".require-trusted-types-for";
    /** Configuration prefix for the {@code script-src} directive. */
    public static final String PROPERTY_SCRIPT_SRC = ContentSecurityPolicyConfigurationProperties.PREFIX + ".script-src";
    /** Configuration prefix for the {@code style-src} directive. */
    public static final String PROPERTY_STYLE_SRC = ContentSecurityPolicyConfigurationProperties.PREFIX + ".style-src";
    /** Configuration prefix for the {@code worker-src} directive. */
    public static final String PROPERTY_WORKER_SRC = ContentSecurityPolicyConfigurationProperties.PREFIX + ".worker-src";

    private static final boolean DEFAULT_ENABLED = true;
    private static final boolean DEFAULT_REPORT_ONLY = false;
    private boolean enabled = DEFAULT_ENABLED;
    private boolean reportOnly = DEFAULT_REPORT_ONLY;

    /**
     * Reports whether the CSP module is enabled.
     *
     * <p>The toggle is applied by a condition that reads the property itself, so that a mistyped
     * value keeps the module's protection; this getter only reports the bound value.</p>
     *
     * @return the bound value of {@code micronaut.security.csp.enabled}
     */
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public boolean isReportOnly() {
        return reportOnly;
    }

    /**
     * Whether to send the policy in the Content-Security-Policy-Report-Only header, which reports
     * violations without blocking them. Default: false.
     *
     * @param reportOnly whether to send the policy using the {@code Content-Security-Policy-Report-Only} header
     */
    public void setReportOnly(boolean reportOnly) {
        this.reportOnly = reportOnly;
    }

    /**
     * Whether the CSP module is enabled. Default: true.
     *
     * @param enabled whether the CSP module is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
