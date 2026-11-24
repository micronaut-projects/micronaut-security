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
import io.micronaut.security.csp.conf.reportto.ReportToConfigurationProperties;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Configures the {@link ContentSecurityPolicyController}.
 *
 * @author Sergio del Amo
 * @since 5.6.0
 */
@Requires(condition = ContentSecurityPolicyControllerEnabledCondition.class)
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

    /**
     * The grammar of the report path: an absolute path that starts with a single slash, so that it
     * cannot name another host, without whitespace, quotes or backslashes.
     */
    static final String LOCAL_PATH_REGEX = "/(?!/)[^\\s\"\\\\]*";

    private boolean enabled = DEFAULT_ENABLED;
    @NotBlank
    @Pattern(regexp = LOCAL_PATH_REGEX)
    private String path = DEFAULT_PATH;

    /**
     * Reports whether the CSP report controller is enabled.
     *
     * <p>The toggle is applied by a condition that reads the property itself; this getter only
     * reports the bound value.</p>
     *
     * @return whether the {@link ContentSecurityPolicyController} is enabled
     */
    public boolean isEnabled() {
        return this.enabled;
    }

    @Override
    public String getPath() {
        return this.path;
    }

    /**
     * Whether the CSP report controller is registered when a report handler bean exists. Default: true.
     *
     * @param enabled whether the controller is enabled; defaults to {@value #DEFAULT_ENABLED}
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Path of the CSP report controller, relative to the server context path. Default: /csp/report.
     *
     * @param path the controller path; defaults to {@value #DEFAULT_PATH}
     */
    public void setPath(String path) {
        this.path = path;
    }
}
