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
package io.micronaut.security.csp.report;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.csp.conf.reportTo.ReportToConfigurationProperties;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Configures the {@link ContentSecurityPolicyController}.
 *
 * @author Sergio del Amo
 * @since 5.4.0
 */
@Requires(property = ContentSecurityPolicyControllerConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE, defaultValue = StringUtils.TRUE)
@ConfigurationProperties(ContentSecurityPolicyControllerConfigurationProperties.PREFIX)
@Internal
final class ContentSecurityPolicyControllerConfigurationProperties implements ContentSecurityPolicyControllerConfiguration {

    public static final String PREFIX = ReportToConfigurationProperties.PREFIX + ".controller";

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;

    /**
     * The default path.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_PATH = "/csp/report";

    private boolean enabled = DEFAULT_ENABLED;
    @NotBlank
    @Pattern(regexp = "/[^\\s\"\\\\]*")
    private String path = DEFAULT_PATH;

    /**
     * Reports whether the CSP report controller is enabled.
     *
     * @return whether the {@link ContentSecurityPolicyController} is enabled
     */
    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    @Override
    public String getPath() {
        return this.path;
    }

    /**
     * Enables or disables the {@link ContentSecurityPolicyController}.
     *
     * @param enabled whether the controller is enabled; defaults to {@value #DEFAULT_ENABLED}
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Sets the path of the {@link ContentSecurityPolicyController}.
     *
     * @param path the controller path; defaults to {@value #DEFAULT_PATH}
     */
    public void setPath(String path) {
        if (StringUtils.isNotEmpty(path)) {
            this.path = path;
        }
    }
}
