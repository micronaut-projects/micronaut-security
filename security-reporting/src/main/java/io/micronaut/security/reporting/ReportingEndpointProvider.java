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

import io.micronaut.http.HttpRequest;
import org.jspecify.annotations.Nullable;

/**
 * Supplies a request-specific Reporting API endpoint.
 *
 * <p>Providers complement endpoints declared through configuration. They are useful when an
 * endpoint URI depends on request routing or tenant context.</p>
 *
 * @since 5.4.0
 */
@FunctionalInterface
public interface ReportingEndpointProvider {
    /**
     * Creates the endpoint to advertise for a request.
     *
     * @param request current HTTP request
     * @return endpoint to add to the request's {@code Reporting-Endpoints} header, or
     * {@code null} when this provider does not contribute an endpoint for the request
     * @since 5.4.0
     */
    @Nullable ReportingEndpoint reportingEndpoint(HttpRequest<?> request);
}
