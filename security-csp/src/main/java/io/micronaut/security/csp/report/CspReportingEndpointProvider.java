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

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.csp.conf.reportTo.ReportToConfiguration;
import io.micronaut.security.reporting.ReportingEndpoint;
import io.micronaut.security.reporting.ReportingEndpointProvider;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;

import java.net.URI;

/**
 * Advertises the handler-backed CSP report controller through the Reporting API module.
 */
@Requires(beans = ContentSecurityPolicyReportHandler.class)
@Singleton
@Internal
final class CspReportingEndpointProvider implements ReportingEndpointProvider {
    private final ReportToConfiguration reportToConfiguration;
    private final ContentSecurityPolicyControllerConfiguration controllerConfiguration;

    /**
     * Creates the CSP reporting endpoint provider.
     *
     * @param reportToConfiguration reporting group configuration
     * @param controllerConfiguration report controller configuration
     */
    CspReportingEndpointProvider(ReportToConfiguration reportToConfiguration,
                                 ContentSecurityPolicyControllerConfiguration controllerConfiguration) {
        this.reportToConfiguration = reportToConfiguration;
        this.controllerConfiguration = controllerConfiguration;
    }

    /**
     * Returns the controller endpoint when both CSP reporting components are enabled.
     *
     * @param request current request
     * @return the CSP controller endpoint, or {@code null} when reporting is disabled
     */
    @Override
    public @Nullable ReportingEndpoint reportingEndpoint(HttpRequest<?> request) {
        if (!reportToConfiguration.isEnabled() || !controllerConfiguration.isEnabled()) {
            return null;
        }
        return new ReportingEndpoint() {

            @Override
            public String getName() {
                return reportToConfiguration.getGroup();
            }

            @Override
            public URI getUrl() {
                return URI.create(controllerConfiguration.getPath());
            }
        };
    }
}
