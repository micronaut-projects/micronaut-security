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
package io.micronaut.security.csp.conf.reporturi;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties;

import java.util.Collections;
import java.util.List;

/**
 * Binds configuration for the deprecated {@code report-uri} directive.
 *
 * @since 5.6.0
 */
@Internal
@ConfigurationProperties(ContentSecurityPolicyConfigurationProperties.PROPERTY_REPORT_URI)
public class ReportUriConfigurationProperties implements ReportUriConfiguration {
    private boolean enabled;
    private List<String> values = Collections.emptyList();

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Whether to write the deprecated report-uri directive. Default: false.
     *
     * @param enabled whether the deprecated {@code report-uri} directive is included in the policy
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public List<String> getValues() {
        return values;
    }

    /**
     * Endpoint URLs written in the deprecated report-uri directive. Default: empty.
     *
     * @param values the endpoint URLs used as the value of the deprecated {@code report-uri} directive
     */
    public void setValues(List<String> values) {
        this.values = values;
    }
}
