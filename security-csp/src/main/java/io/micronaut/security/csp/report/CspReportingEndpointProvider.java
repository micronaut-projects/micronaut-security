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

import io.micronaut.context.annotation.Context;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.context.ServerContextPathProvider;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.runtime.context.scope.refresh.RefreshEvent;
import io.micronaut.runtime.context.scope.refresh.RefreshEventListener;
import io.micronaut.security.csp.ContentSecurityPolicyGenerator;
import io.micronaut.security.csp.DefaultContentSecurityPolicyGenerator;
import io.micronaut.security.csp.conf.reportto.ReportToConfiguration;
import io.micronaut.security.csp.conf.reportto.ReportToConfigurationProperties;
import io.micronaut.security.csp.conf.reporturi.ReportUriConfiguration;
import io.micronaut.security.reporting.ReportingEndpoint;
import io.micronaut.security.reporting.ReportingEndpointProvider;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Advertises the handler-backed CSP report controller through the Reporting API module.
 *
 * <p>It exists only under the same conditions as the controller: while {@code report-to} is
 * disabled, the provider would advertise nothing, yet its presence alone would add the Reporting API
 * response filter to every request.</p>
 *
 * <p>The bean is created at startup, so that an invalid controller path or reporting group fails
 * application startup instead of every response. The advertised endpoint name follows the
 * {@code report-to} directive of the default generator's current policy, so a refresh that the
 * generator accepts changes both and a refresh that it rejects changes neither. With another
 * generator, the name follows the {@code report-to} group configuration. When an endpoint configured through the Reporting API module already uses the group
 * name, the provider advertises nothing and lets that endpoint receive the reports.</p>
 */
@Requires(condition = ReportToEnabledCondition.class)
@Requires(beans = { ContentSecurityPolicyReportHandler.class, ReportToConfiguration.class, ContentSecurityPolicyControllerConfiguration.class,
    ContentSecurityPolicyReportBodyReader.class })
@Context
@Internal
final class CspReportingEndpointProvider implements ReportingEndpointProvider, RefreshEventListener {
    private static final Logger LOG = LoggerFactory.getLogger(CspReportingEndpointProvider.class);
    private static final String SLASH = "/";
    private static final Pattern LOCAL_PATH = Pattern.compile(ContentSecurityPolicyControllerConfigurationProperties.LOCAL_PATH_REGEX);
    private final ReportToConfiguration reportToConfiguration;
    private final @Nullable DefaultContentSecurityPolicyGenerator defaultGenerator;
    private final List<ReportingEndpoint> staticEndpoints;
    private final URI url;
    /**
     * The validated group configuration, used only when the default generator is not in use.
     */
    private volatile String configuredGroup;
    private volatile Advertised advertised;

    /**
     * Creates the CSP reporting endpoint provider.
     *
     * @param reportToConfiguration reporting group configuration
     * @param controllerConfiguration report controller configuration
     * @param serverContextPathProvider supplies the server context path under which the controller is mounted, if any
     * @param staticEndpoints the reporting endpoints configured through the Reporting API module
     * @param cspGenerator the policy generator, whose {@code report-to} directive the endpoint follows
     * @param reportUriConfiguration the deprecated {@code report-uri} configuration, checked for the controller path
     */
    CspReportingEndpointProvider(ReportToConfiguration reportToConfiguration,
                                 ContentSecurityPolicyControllerConfiguration controllerConfiguration,
                                 @Nullable ServerContextPathProvider serverContextPathProvider,
                                 List<ReportingEndpoint> staticEndpoints,
                                 ContentSecurityPolicyGenerator cspGenerator,
                                 ReportUriConfiguration reportUriConfiguration) {
        this.reportToConfiguration = reportToConfiguration;
        this.defaultGenerator = cspGenerator instanceof DefaultContentSecurityPolicyGenerator generator ? generator : null;
        this.staticEndpoints = staticEndpoints;
        this.url = url(requireLocalPath(controllerConfiguration.getPath()), serverContextPathProvider);
        this.configuredGroup = ReportToConfigurationProperties.requireValidGroup(reportToConfiguration.getGroup());
        this.advertised = new Advertised(configuredGroup, endpoint(configuredGroup));
        warnIfReportUriTargetsTheController(reportUriConfiguration);
    }

    /**
     * Warns when {@code report-uri} points at the report controller: browsers send {@code report-uri}
     * reports as {@code application/csp-report}, which the controller rejects with HTTP 415.
     *
     * @param reportUriConfiguration the {@code report-uri} configuration
     */
    private void warnIfReportUriTargetsTheController(ReportUriConfiguration reportUriConfiguration) {
        if (!reportUriConfiguration.isEnabled()) {
            return;
        }
        for (String value : reportUriConfiguration.getValues()) {
            if (url.getPath().equals(path(value))) {
                LOG.warn("micronaut.security.csp.report-uri.values contains {}, the CSP report controller. Browsers send report-uri reports "
                    + "as application/csp-report, which the controller rejects with HTTP 415; it only receives report-to reports. "
                    + "Remove the value or point it at an endpoint that accepts application/csp-report.", value.trim());
            }
        }
    }

    private static @Nullable String path(String value) {
        try {
            return URI.create(value.trim()).getPath();
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Returns the controller endpoint.
     *
     * @param request current request
     * @return the CSP controller endpoint, or {@code null} when a configured endpoint already uses the reporting group
     */
    @Override
    public @Nullable ReportingEndpoint reportingEndpoint(HttpRequest<?> request) {
        String group = defaultGenerator == null ? configuredGroup : defaultGenerator.reportToGroup();
        if (group == null) {
            return null;
        }
        Advertised current = advertised;
        if (!group.equals(current.group())) {
            current = new Advertised(group, endpoint(group));
            advertised = current;
        }
        return current.endpoint();
    }

    @Override
    public Set<String> getObservedConfigurationPrefixes() {
        return Set.of(ReportToConfigurationProperties.PREFIX);
    }

    /**
     * Reads the refreshed reporting group when the default generator is not in use; the default
     * generator validates its own refresh. An invalid group is logged and the previous one is kept.
     *
     * @param event the refresh event
     */
    @Override
    public void onApplicationEvent(RefreshEvent event) {
        if (defaultGenerator != null) {
            return;
        }
        try {
            configuredGroup = ReportToConfigurationProperties.requireValidGroup(reportToConfiguration.getGroup());
        } catch (ConfigurationException e) {
            LOG.error("Keeping the previous CSP reporting group because the refreshed configuration is invalid: {}", e.getMessage());
        }
    }

    /**
     * Builds the endpoint advertised for a reporting group, unless a configured endpoint already
     * declares the group: the Reporting API module keeps the configured endpoint and would log a
     * warning on every response about the duplicate name.
     *
     * @param group the validated reporting group
     * @return the endpoint, or {@code null} when a configured endpoint already uses the group
     */
    private @Nullable ReportingEndpoint endpoint(String group) {
        for (ReportingEndpoint staticEndpoint : staticEndpoints) {
            if (group.equals(staticEndpoint.getName())) {
                if (!url.equals(staticEndpoint.getUrl())) {
                    LOG.warn("The reporting endpoint '{}' configured through the Reporting API module receives the CSP reports at {}, "
                        + "so the ContentSecurityPolicyReportHandler bean, served at {}, receives none. Remove that endpoint or change "
                        + "micronaut.security.csp.report-to.group.", group, staticEndpoint.getUrl(), url);
                }
                return null;
            }
        }
        return new ReportingEndpoint() {
            @Override
            public String getName() {
                return group;
            }

            @Override
            public URI getUrl() {
                return url;
            }
        };
    }

    /**
     * Rejects a controller path that would advertise another origin, or break the header, in
     * {@code Reporting-Endpoints}. This is the bean-validation constraint of the property, applied
     * also without micronaut-validation at runtime.
     *
     * @param path the configured controller path
     * @return the path
     * @throws ConfigurationException if the path is not a local absolute path
     */
    private static String requireLocalPath(String path) {
        if (!LOCAL_PATH.matcher(path).matches()) {
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

    /**
     * The endpoint advertised for a reporting group.
     *
     * @param group the reporting group
     * @param endpoint the endpoint, or {@code null} when a configured endpoint already uses the group
     */
    private record Advertised(String group, @Nullable ReportingEndpoint endpoint) {
    }
}
