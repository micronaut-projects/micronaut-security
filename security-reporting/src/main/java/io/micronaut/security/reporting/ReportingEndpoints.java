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

import java.util.Collection;
import java.util.Comparator;
import java.util.StringJoiner;

/**
 * An unmodifiable collection of endpoints serialized as a {@code Reporting-Endpoints} header value.
 *
 * <p>The header uses the HTTP Structured Fields dictionary format. Endpoint entries are therefore
 * separated by commas, names use the dictionary-key grammar, and URI references are serialized as
 * quoted string values.</p>
 *
 * <p>Endpoints are serialized in endpoint-name order to produce a deterministic header. Endpoint
 * order has no effect on Reporting API processing.</p>
 *
 * @param endpoints endpoints to advertise
 * @since 5.4.0
 */
public record ReportingEndpoints(Collection<ReportingEndpoint> endpoints) {
    /** Standard Reporting API response-header name. */
    public static final String HEADER_NAME = "Reporting-Endpoints";

    private static final Comparator<ReportingEndpoint> ENDPOINT_COMPARATOR =
        Comparator.comparing(ReportingEndpoint::getName)
            .thenComparing(endpoint -> endpoint.getUrl().toASCIIString());

    /**
     * Creates an immutable endpoint collection in deterministic serialization order.
     *
     * @param endpoints endpoints to advertise
     * @since 5.4.0
     */
    public ReportingEndpoints {
        endpoints = endpoints.stream().sorted(ENDPOINT_COMPARATOR).toList();
    }

    /**
     * Serializes the endpoints as an HTTP Structured Fields dictionary.
     *
     * @return the {@code Reporting-Endpoints} response-header value
     */
    @Override
    public String toString() {
        StringJoiner joiner = new StringJoiner(", ");
        for (ReportingEndpoint endpoint : endpoints()) {
            joiner.add(endpoint.getName() + "=\"" + endpoint.getUrl().toASCIIString() + "\"");
        }
        return joiner.toString();
    }
}
