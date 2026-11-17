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

import io.micronaut.context.annotation.Context;
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

/**
 * Advertises configured Reporting API endpoints on matching HTTP responses.
 *
 * <p>An application-supplied {@code Reporting-Endpoints} header takes precedence. Static
 * {@link ReportingEndpoint} beans and request-specific {@link ReportingEndpointProvider} beans
 * contribute entries; when neither contributes an endpoint, the filter omits the header.</p>
 *
 * <p>Endpoint names must be Structured Fields dictionary keys. A static endpoint with an invalid
 * name fails at startup, because the filter is created eagerly. A request-specific endpoint with an invalid name is
 * logged and omitted, so that a misbehaving provider cannot fail the response.</p>
 */
@Requires(classes = ServerFilter.class)
@Requires(condition = ReportingEndpointsFilterCondition.class)
@ServerFilter("${" + ReportingEndpointsFilterConfigurationProperties.PREFIX + ".pattern:" + ServerFilter.MATCH_ALL_PATTERN + "}")
@Context
@Internal
final class ReportingEndpointsFilter {
    private static final Logger LOG = LoggerFactory.getLogger(ReportingEndpointsFilter.class);

    private final List<ReportingEndpoint> reportingEndpoints;
    private final List<ReportingEndpointProvider> reportingEndpointProviders;

    /**
     * Creates the filter from every static endpoint and request-specific endpoint provider.
     *
     * @param reportingEndpoints static endpoints to advertise
     * @param reportingEndpointProviders request-specific endpoint providers
     * @throws IllegalArgumentException when a static endpoint name is not a valid Structured
     * Fields dictionary key (RFC 8941)
     */
    ReportingEndpointsFilter(List<ReportingEndpoint> reportingEndpoints,
                             List<ReportingEndpointProvider> reportingEndpointProviders) {
        for (ReportingEndpoint endpoint : reportingEndpoints) {
            ReportingEndpointNames.require(endpoint.getName());
        }
        this.reportingEndpoints = List.copyOf(reportingEndpoints);
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
                if (ReportingEndpointNames.isValid(endpoint.getName())) {
                    endpoints.add(endpoint);
                } else if (LOG.isWarnEnabled()) {
                    // The rejected name may derive from the request, so it is not logged.
                    LOG.warn("Ignoring the reporting endpoint supplied by {}: its name is not a valid Structured Fields dictionary key (RFC 8941); it must match {}",
                        provider.getClass().getName(), ReportingEndpointNames.KEY_GRAMMAR);
                }
            }
            if (!endpoints.isEmpty()) {
                response.header(ReportingEndpoints.HEADER_NAME, new ReportingEndpoints(endpoints).toString());
            }
        }
    }
}
