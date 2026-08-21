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

import io.micronaut.context.annotation.EachProperty;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.core.annotation.Internal;

import java.net.URI;

/**
 * Binds one named entry under {@value #PREFIX}.
 *
 * <p>For example, {@code micronaut.security.reporting-endpoints.csp.url=/csp/report} creates the
 * endpoint named {@code csp} with the relative URI {@code /csp/report}.</p>
 *
 * @since 5.4.0
 */
@EachProperty(ReportingEndpointConfiguration.PREFIX)
@Internal
final class ReportingEndpointConfiguration implements ReportingEndpoint {
    /** Configuration prefix for named Reporting API endpoints. */
    public static final String PREFIX = "micronaut.security.reporting-endpoints";

    private final String name;

    private URI url;

    /**
     * Creates a named endpoint configuration.
     *
     * @param name configuration entry name and Reporting API endpoint name
     * @since 5.4.0
     */
    public ReportingEndpointConfiguration(@Parameter String name) {
        this.name = name;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getName() {
        return name;
    }

    /**
     * {@inheritDoc}
     *
     * @throws IllegalStateException if the required {@code url} property was not configured
     */
    @Override
    public URI getUrl() {
        return url;
    }

    /**
     * Sets the absolute or relative reporting endpoint URI.
     *
     * @param url reporting endpoint URI reference
     * @since 5.4.0
     */
    public void setUrl(URI url) {
        this.url = url;
    }
}
