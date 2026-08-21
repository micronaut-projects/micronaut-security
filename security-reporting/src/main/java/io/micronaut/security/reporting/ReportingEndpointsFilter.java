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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Advertises configured Reporting API endpoints on matching HTTP responses.
 *
 * <p>An application-supplied {@code Reporting-Endpoints} header takes precedence. Static
 * {@link ReportingEndpoint} beans and request-specific {@link ReportingEndpointProvider} beans
 * contribute entries; when neither contributes an endpoint, the filter omits the header.</p>
 */
@Requires(condition = ReportingEndpointsFilterCondition.class)
@ServerFilter("${" + ReportingEndpointsFilterConfigurationProperties.PREFIX + ".pattern:" + ServerFilter.MATCH_ALL_PATTERN + "}")
@Internal
final class ReportingEndpointsFilter {
    private final List<ReportingEndpoint> reportingEndpoints;
    private final List<ReportingEndpointProvider> reportingEndpointProviders;

    /**
     * Creates the filter from every static endpoint and request-specific endpoint provider.
     *
     * @param reportingEndpoints static endpoints to advertise
     * @param reportingEndpointProviders request-specific endpoint providers
     */
    ReportingEndpointsFilter(List<ReportingEndpoint> reportingEndpoints,
                             List<ReportingEndpointProvider> reportingEndpointProviders) {
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
                endpoints.add(provider.reportingEndpoint(request));
            }
            endpoints = endpoints.stream().filter(Objects::nonNull).toList();
            if (!endpoints.isEmpty()) {
                response.header(ReportingEndpoints.HEADER_NAME, new ReportingEndpoints(endpoints).toString());
            }
        }
    }
}
