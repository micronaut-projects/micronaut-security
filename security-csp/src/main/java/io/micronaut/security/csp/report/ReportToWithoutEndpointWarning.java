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
import io.micronaut.context.event.ApplicationEventListener;
import io.micronaut.context.event.StartupEvent;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.csp.conf.reportto.ReportToConfiguration;
import io.micronaut.security.reporting.ReportingEndpoint;
import io.micronaut.security.reporting.ReportingEndpointProvider;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Warns at startup when the {@code report-to} directive names a reporting group that no
 * {@code Reporting-Endpoints} entry declares, because browsers then discard every report.
 *
 * <p>The module declares the group itself through {@link CspReportingEndpointProvider}, which
 * exists only when a {@link ContentSecurityPolicyReportHandler} bean exists and the report
 * controller is enabled, so this check runs whenever that provider is missing. Endpoints configured
 * through the Reporting API module are taken into account. The endpoints of
 * {@link ReportingEndpointProvider} beans depend on the request, and a header written by the
 * application itself cannot be detected, so while such a provider exists the message is logged at
 * INFO instead of WARN.</p>
 */
@Requires(condition = ReportToEnabledCondition.class)
@Requires(missingBeans = CspReportingEndpointProvider.class)
@Singleton
@Internal
final class ReportToWithoutEndpointWarning implements ApplicationEventListener<StartupEvent> {
    private static final Logger LOG = LoggerFactory.getLogger(ReportToWithoutEndpointWarning.class);
    private final ReportToConfiguration reportToConfiguration;
    private final List<ReportingEndpoint> reportingEndpoints;
    private final List<ReportingEndpointProvider> reportingEndpointProviders;

    /**
     * Creates the startup check.
     *
     * @param reportToConfiguration the {@code report-to} configuration
     * @param reportingEndpoints the reporting endpoints configured through the Reporting API module
     * @param reportingEndpointProviders the providers of request-specific reporting endpoints
     */
    ReportToWithoutEndpointWarning(ReportToConfiguration reportToConfiguration,
                                   List<ReportingEndpoint> reportingEndpoints,
                                   List<ReportingEndpointProvider> reportingEndpointProviders) {
        this.reportToConfiguration = reportToConfiguration;
        this.reportingEndpoints = reportingEndpoints;
        this.reportingEndpointProviders = reportingEndpointProviders;
    }

    @Override
    public void onApplicationEvent(StartupEvent event) {
        String group = reportToConfiguration.getGroup();
        boolean declared = reportingEndpoints.stream().anyMatch(endpoint -> group.equals(endpoint.getName()));
        if (declared) {
            return;
        }
        String message = "The CSP report-to group '{}' has no reporting endpoint, so browsers discard the reports. Add a "
            + "ContentSecurityPolicyReportHandler bean with an enabled report controller, or configure "
            + "micronaut.security.reporting-endpoints.{}.url, unless a ReportingEndpointProvider bean or the application's own "
            + "Reporting-Endpoints header declares it.";
        if (reportingEndpointProviders.isEmpty()) {
            LOG.warn(message, group, group);
        } else {
            LOG.info(message, group, group);
        }
    }
}
