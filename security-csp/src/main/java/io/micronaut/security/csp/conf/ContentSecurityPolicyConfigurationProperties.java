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

import java.util.Collections;
import java.util.List;

import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.SCRIPT;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.SINGLE_QUOTE;

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
    public static final String PREFIX = "micronaut.security.csp";
    private static final String SCRIPT_VALUE = SINGLE_QUOTE + SCRIPT + SINGLE_QUOTE;
    private static final boolean DEFAULT_ENABLED = true;
    private static final boolean DEFAULT_REPORT_ONLY = false;
    private static final boolean DEFAULT_REPORT_URI_ENABLED = false;
    private static final List<String> DEFAULT_REPORT_URI_VALUE = Collections.emptyList();
    private static final boolean DEFAULT_REQUIRE_TRUSTED_TYPES_FOR_ENABLED = true;
    private static final String DEFAULT_REQUIRE_TRUSTED_TYPES_FOR_VALUE = SCRIPT_VALUE;
    private boolean enabled = DEFAULT_ENABLED;
    private boolean reportOnly = DEFAULT_REPORT_ONLY;
    private boolean reportUriEnabled = DEFAULT_REPORT_URI_ENABLED;
    private List<String> reportUri = DEFAULT_REPORT_URI_VALUE;
    private boolean requireTrustedTypesForEnabled = DEFAULT_REQUIRE_TRUSTED_TYPES_FOR_ENABLED;
    private String requireTrustedTypesFor = DEFAULT_REQUIRE_TRUSTED_TYPES_FOR_VALUE;

    @Override
    public boolean isReportUriEnabled() {
        return reportUriEnabled;
    }

    /**
     * @param reportUriEnabled whether the deprecated {@code report-uri} directive is included in the policy
     */
    public void setReportUriEnabled(boolean reportUriEnabled) {
        this.reportUriEnabled = reportUriEnabled;
    }

    @Override
    public List<String> getReportUri() {
        return reportUri;
    }

    /**
     * @param reportUri the endpoint URLs used as the value of the deprecated {@code report-uri} directive
     */
    public void setReportUri(List<String> reportUri) {
        this.reportUri = reportUri;
    }

    @Override
    public boolean isRequireTrustedTypesForEnabled() {
        return requireTrustedTypesForEnabled;
    }

    /**
     * @param requireTrustedTypesForEnabled whether the {@code require-trusted-types-for} directive is included in the policy
     */
    public void setRequireTrustedTypesForEnabled(boolean requireTrustedTypesForEnabled) {
        this.requireTrustedTypesForEnabled = requireTrustedTypesForEnabled;
    }

    @Override
    public String getRequireTrustedTypesFor() {
        return requireTrustedTypesFor;
    }

    /**
     * @param requireTrustedTypesFor the sink group required to use Trusted Types
     */
    public void setRequireTrustedTypesFor(String requireTrustedTypesFor) {
        this.requireTrustedTypesFor = requireTrustedTypesFor;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public boolean isReportOnly() {
        return reportOnly;
    }

    /**
     * @param reportOnly whether to send the policy using the {@code Content-Security-Policy-Report-Only} header
     */
    public void setReportOnly(boolean reportOnly) {
        this.reportOnly = reportOnly;
    }

    /**
     * @param enabled whether the CSP module is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
