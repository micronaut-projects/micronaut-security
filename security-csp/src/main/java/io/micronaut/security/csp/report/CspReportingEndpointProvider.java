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
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.context.ServerContextPathProvider;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.security.csp.conf.reportto.ReportToConfiguration;
import io.micronaut.security.csp.conf.reportto.ReportToConfigurationProperties;
import io.micronaut.security.reporting.ReportingEndpoint;
import io.micronaut.security.reporting.ReportingEndpointProvider;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.util.regex.Pattern;

/**
 * Advertises the handler-backed CSP report controller through the Reporting API module.
 */
@Requires(beans = { ContentSecurityPolicyReportHandler.class, ReportToConfiguration.class, ContentSecurityPolicyControllerConfiguration.class })
@Singleton
@Internal
final class CspReportingEndpointProvider implements ReportingEndpointProvider {
    private static final String SLASH = "/";
    private static final Pattern LOCAL_PATH = Pattern.compile(ContentSecurityPolicyControllerConfigurationProperties.LOCAL_PATH_REGEX);
    private static final Pattern GROUP = Pattern.compile(ReportToConfigurationProperties.GROUP_REGEX);
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
            String name = requireGroup(reportToConfiguration.getGroup());
            URI url = url(requireLocalPath(controllerConfiguration.getPath()), serverContextPathProvider);
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
     * Rejects a group name that the {@code Reporting-Endpoints} header cannot carry. Without this
     * check, which applies whichever policy generator is in use and without micronaut-validation,
     * the reporting filter would drop the endpoint and warn on every response.
     *
     * @param group the configured reporting group
     * @return the group
     * @throws ConfigurationException if the group does not match {@link ReportToConfigurationProperties#GROUP_REGEX}
     */
    private static String requireGroup(String group) {
        if (!GROUP.matcher(group).matches()) {
            throw new ConfigurationException(ReportToConfigurationProperties.PREFIX + ".group must match "
                + ReportToConfigurationProperties.GROUP_REGEX + ", the grammar of a Reporting-Endpoints name");
        }
        return group;
    }

    /**
     * Rejects a controller path that would advertise another origin, or break the header, in
     * {@code Reporting-Endpoints}. This mirrors the bean-validation constraint on the property so
     * that it also applies without micronaut-validation at runtime.
     *
     * @param path the configured controller path
     * @return the path
     * @throws ConfigurationException if the path is not a local absolute path
     */
    private static String requireLocalPath(String path) {
        if (!LOCAL_PATH.matcher(path).matches() || path.startsWith("//")) {
            throw new ConfigurationException(ContentSecurityPolicyControllerConfigurationProperties.PREFIX
                + ".path must be an absolute path on this server, starting with a single '/' and without whitespace, quotes or backslashes");
        }
        return path;
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
            return UriBuilder.of(SLASH).path(contextPath).path(path).build();
        }
        return URI.create(path);
    }
}
