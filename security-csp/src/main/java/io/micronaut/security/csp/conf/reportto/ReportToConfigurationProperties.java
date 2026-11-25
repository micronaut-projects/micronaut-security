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
package io.micronaut.security.csp.conf.reportto;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.csp.ContentSecurityPolicyUtils;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Binds configuration for the {@code report-to} directive.
 *
 * <p>The directive is disabled by default because applications must deliberately select and
 * implement a reporting endpoint.</p>
 *
 * @since 5.6.0
 */
@Internal
@ConfigurationProperties(ReportToConfigurationProperties.PREFIX)
public class ReportToConfigurationProperties implements ReportToConfiguration {
    /** Configuration prefix for the {@code report-to} directive. */
    public static final String PREFIX = ContentSecurityPolicyConfigurationProperties.PREFIX + ".report-to";

    /** Default Reporting API endpoint group. */
    public static final String DEFAULT_GROUP = "csp";

    /**
     * The grammar of a Reporting API endpoint group name, the {@code sf-key} grammar of the
     * {@code Reporting-Endpoints} header.
     */
    public static final String GROUP_REGEX = "[a-z*][a-z0-9_.*-]*";

    /**
     * Explains the grammar of a reporting group.
     */
    static final String GROUP_MESSAGE = "must start with a lowercase letter or * and use only lowercase letters, digits and _ . * -, for example csp";

    private static final java.util.regex.Pattern GROUP_PATTERN = java.util.regex.Pattern.compile(GROUP_REGEX);

    private boolean enabled;

    @NotBlank
    @Pattern(regexp = GROUP_REGEX, message = GROUP_MESSAGE)
    private String group = DEFAULT_GROUP;

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Whether to write the report-to directive. Default: false.
     *
     * @param enabled whether the generated policy includes {@code report-to}
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public String getGroup() {
        return group;
    }

    /**
     * Reporting API endpoint group named in the report-to directive and, when a report handler exists, in
     * the Reporting-Endpoints header. Use lowercase letters, digits and the characters _ . * - only.
     * Default: csp.
     *
     * @param group Reporting API endpoint group referenced by {@code report-to}
     */
    public void setGroup(String group) {
        this.group = group;
    }

    /**
     * Rejects a group name that the {@code Reporting-Endpoints} header cannot carry. The policy
     * generator and the module's reporting endpoint both apply this check, so that it holds without
     * micronaut-validation and whichever of them reads the group.
     *
     * @param group the configured reporting group
     * @return the group
     * @throws ConfigurationException if the group does not match {@link #GROUP_REGEX}
     */
    public static String requireValidGroup(String group) {
        if (!GROUP_PATTERN.matcher(group).matches()) {
            throw new ConfigurationException(PREFIX + ".group is \"" + ContentSecurityPolicyUtils.printable(group) + "\"; it " + GROUP_MESSAGE
                + ", the grammar of a Reporting-Endpoints name");
        }
        return group;
    }
}
