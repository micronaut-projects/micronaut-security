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
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.context.ServerContextPathProvider;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.security.csp.conf.reportto.ReportToConfiguration;
import io.micronaut.security.reporting.ReportingEndpoint;
import io.micronaut.security.reporting.ReportingEndpointProvider;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;

import java.net.URI;

/**
 * Advertises the handler-backed CSP report controller through the Reporting API module.
 */
@Requires(beans = { ContentSecurityPolicyReportHandler.class, ReportToConfiguration.class, ContentSecurityPolicyControllerConfiguration.class })
@Singleton
@Internal
final class CspReportingEndpointProvider implements ReportingEndpointProvider {
    private final @Nullable ReportingEndpoint reportingEndpoint;

    /**
     * Creates the CSP reporting endpoint provider.
     *
     * @param reportToConfiguration reporting group configuration
     * @param controllerConfiguration report controller configuration
     * @param serverContextPathProvider supplies the server context path under which the controller is mounted, if any
     */
    CspReportingEndpointProvider(ReportToConfiguration reportToConfiguration,
                                 ContentSecurityPolicyControllerConfiguration controllerConfiguration,
                                 @Nullable ServerContextPathProvider serverContextPathProvider) {
        if (reportToConfiguration.isEnabled()) {
            String name = reportToConfiguration.getGroup();
            URI url = url(controllerConfiguration.getPath(), serverContextPathProvider);
            this.reportingEndpoint = new ReportingEndpoint() {
                @Override
                public String getName() {
                    return name;
                }

                @Override
                public URI getUrl() {
                    return url;
                }
            };
        } else {
            this.reportingEndpoint = null;
        }
    }

    /**
     * Returns the controller endpoint when the {@code report-to} directive is enabled.
     *
     * <p>The endpoint is built once: the controller configuration bean exists only while the
     * controller is enabled, and the configuration does not change at runtime.</p>
     *
     * @param request current request
     * @return the CSP controller endpoint, or {@code null} when reporting is disabled
     */
    @Override
    public @Nullable ReportingEndpoint reportingEndpoint(HttpRequest<?> request) {
        return reportingEndpoint;
    }

    /**
     * Resolves the controller path against the server context path, because user agents send
     * reports to the advertised URL as-is.
     *
     * @param path the controller path
     * @param serverContextPathProvider supplies the server context path, if any
     * @return the URL advertised in the {@code Reporting-Endpoints} header
     */
    private static URI url(String path, @Nullable ServerContextPathProvider serverContextPathProvider) {
        String contextPath = serverContextPathProvider == null ? null : serverContextPathProvider.getContextPath();
        if (StringUtils.hasText(contextPath)) {
            return UriBuilder.of("/").path(contextPath).path(path).build();
        }
        return URI.create(path);
    }
}
