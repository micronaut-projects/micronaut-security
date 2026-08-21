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
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import java.net.URI;
import java.util.Objects;

/**
 * Binds one named entry under {@value #PREFIX}.
 *
 * <p>For example, {@code micronaut.security.reporting-endpoints.csp.url=/csp/report} creates the
 * endpoint named {@code csp} with the relative URI {@code /csp/report}.</p>
 *
 * @since 5.4.0
 */
@EachProperty(ReportingEndpointConfiguration.PREFIX)
public final class ReportingEndpointConfiguration implements ReportingEndpoint {
    /** Configuration prefix for named Reporting API endpoints. */
    public static final String PREFIX = "micronaut.security.reporting-endpoints";

    @Pattern(regexp = "[a-z*][a-z0-9_.*-]*")
    @NotBlank
    private final String name;

    private @NotNull URI url;

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
        if (url == null) {
            throw new IllegalStateException("Missing reporting endpoint URL for group: " + name);
        }
        return url;
    }

    /**
     * Sets the absolute or relative reporting endpoint URI.
     *
     * @param url reporting endpoint URI reference
     * @since 5.4.0
     */
    public void setUrl(URI url) {
        this.url = Objects.requireNonNull(url, "url");
    }
}
