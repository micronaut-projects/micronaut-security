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
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.Internal;

import java.net.URI;
import java.util.Locale;

/**
 * Binds one named entry under {@value #PREFIX}.
 *
 * <p>For example, {@code micronaut.security.reporting-endpoints.csp.url=/csp/report} creates the
 * endpoint named {@code csp} with the relative URI {@code /csp/report}.</p>
 *
 * <p>The entry name becomes a Structured Fields dictionary key in the {@code Reporting-Endpoints}
 * header, so it is lower-cased and must then match {@code [a-z*][a-z0-9_\-.*]*}; any other name
 * fails at startup.</p>
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
     * <p>The name is lower-cased so that, for example, {@code Csp} becomes {@code csp}.</p>
     *
     * @param name configuration entry name and Reporting API endpoint name
     * @throws ConfigurationException when the lower-cased name is not a valid Structured Fields
     * dictionary key (RFC 8941)
     * @since 5.4.0
     */
    public ReportingEndpointConfiguration(@Parameter String name) {
        String key = name == null ? null : name.toLowerCase(Locale.ROOT);
        if (!ReportingEndpointNames.isValid(key)) {
            throw new ConfigurationException("Invalid value for property " + PREFIX + "." + name + ": "
                + ReportingEndpointNames.describeInvalid(key));
        }
        this.name = key;
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
