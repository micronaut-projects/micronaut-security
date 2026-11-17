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
package io.micronaut.security.reporting;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.ResponseFilter;
import io.micronaut.http.annotation.ServerFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Advertises configured Reporting API endpoints on matching HTTP responses.
 *
 * <p>An application-supplied {@code Reporting-Endpoints} header takes precedence. Static
 * {@link ReportingEndpoint} beans and request-specific {@link ReportingEndpointProvider} beans
 * contribute entries; when neither contributes an endpoint, the filter omits the header.</p>
 *
 * <p>Endpoint names must be Structured Fields dictionary keys and endpoints must have a URL. An
 * endpoint failing either check, whether static or request-specific, is omitted, so that it can
 * neither fail the response nor make user agents discard the whole header. A warning is logged once per static endpoint and
 * once per provider type, so that request-derived names cannot flood the log.</p>
 */
@Requires(classes = ServerFilter.class)
@Requires(condition = ReportingEndpointsFilterCondition.class)
@ServerFilter("${" + ReportingEndpointsFilterConfigurationProperties.PREFIX + ".pattern:" + ServerFilter.MATCH_ALL_PATTERN + "}")
@Internal
final class ReportingEndpointsFilter {
    private static final Logger LOG = LoggerFactory.getLogger(ReportingEndpointsFilter.class);

    private final List<ReportingEndpoint> reportingEndpoints;
    private final List<ReportingEndpointProvider> reportingEndpointProviders;
    private final Set<Class<?>> warnedProviders = ConcurrentHashMap.newKeySet();

    /**
     * Creates the filter from every static endpoint and request-specific endpoint provider.
     *
     * <p>Static endpoints whose name is not a valid Structured Fields dictionary key (RFC 8941),
     * or that have no URL, are logged once here and omitted.</p>
     *
     * @param reportingEndpoints static endpoints to advertise
     * @param reportingEndpointProviders request-specific endpoint providers
     */
    ReportingEndpointsFilter(List<ReportingEndpoint> reportingEndpoints,
                             List<ReportingEndpointProvider> reportingEndpointProviders) {
        List<ReportingEndpoint> validEndpoints = new ArrayList<>(reportingEndpoints.size());
        for (ReportingEndpoint endpoint : reportingEndpoints) {
            if (ReportingEndpointUtils.isValid(endpoint)) {
                validEndpoints.add(endpoint);
            } else if (LOG.isWarnEnabled()) {
                LOG.warn("Ignoring the reporting endpoint named \"{}\" ({}): it needs a URL and a name that is a valid Structured Fields dictionary key (RFC 8941) matching {}",
                    endpoint.getName(), endpoint.getClass().getName(), ReportingEndpointNames.KEY_GRAMMAR);
            }
        }
        this.reportingEndpoints = List.copyOf(validEndpoints);
        this.reportingEndpointProviders = List.copyOf(reportingEndpointProviders);
    }

    /**
     * Adds the endpoint dictionary unless application code already supplied the header.
     *
     * @param request current request passed to endpoint providers
     * @param response response to which the header may be added
     */
    @ResponseFilter
    void filter(HttpRequest<?> request, MutableHttpResponse<?> response) {
        if (!response.getHeaders().contains(ReportingEndpoints.HEADER_NAME)) {
            List<ReportingEndpoint> endpoints = new ArrayList<>(reportingEndpoints);
            for (ReportingEndpointProvider provider : reportingEndpointProviders) {
                ReportingEndpoint endpoint = provider.reportingEndpoint(request);
                if (endpoint == null) {
                    continue;
                }
                if (ReportingEndpointUtils.isValid(endpoint)) {
                    endpoints.add(endpoint);
                } else if (warnedProviders.add(provider.getClass())) {
                    // The rejected name may derive from the request, so it is not logged, and
                    // the warning is emitted once per provider type rather than per request.
                    LOG.warn("Ignoring reporting endpoints supplied by {} that have no URL or whose name is not a valid Structured Fields dictionary key (RFC 8941) matching {}. This warning is logged once.",
                        provider.getClass().getName(), ReportingEndpointNames.KEY_GRAMMAR);
                }
            }
            if (!endpoints.isEmpty()) {
                response.header(ReportingEndpoints.HEADER_NAME, new ReportingEndpoints(endpoints).toString());
            }
        }
    }
}
