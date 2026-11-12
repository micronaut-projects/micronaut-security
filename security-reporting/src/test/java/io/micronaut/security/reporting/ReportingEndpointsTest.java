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

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ReportingEndpointsTest {

    @Test
    void headerNameIsReportingEndpoints() {
        assertEquals("Reporting-Endpoints", ReportingEndpoints.HEADER_NAME);
    }

    @Test
    void serializesAnEmptyCollectionAsAnEmptyValue() {
        assertEquals("", new ReportingEndpoints(List.of()).toString());
    }

    @Test
    void serializesRelativeAndAbsoluteEndpointUris() {
        ReportingEndpoints reportingEndpoints = new ReportingEndpoints(List.of(
            endpoint("network", "https://reports.example.com/network"),
            endpoint("csp", "/csp/report")
        ));

        assertEquals("csp=\"/csp/report\", network=\"https://reports.example.com/network\"",
            reportingEndpoints.toString());
    }

    @Test
    void sortsEndpointsByNameAndThenUri() {
        ReportingEndpoint second = endpoint("reports", "/reports/b");
        ReportingEndpoint first = endpoint("reports", "/reports/a");
        ReportingEndpoint alphabeticallyFirst = endpoint("errors", "/errors");

        ReportingEndpoints reportingEndpoints = new ReportingEndpoints(
            List.of(second, first, alphabeticallyFirst)
        );

        assertEquals(List.of(alphabeticallyFirst, first, second), reportingEndpoints.endpoints());
    }

    @Test
    void serializesUrisAsAscii() {
        ReportingEndpoints reportingEndpoints = new ReportingEndpoints(List.of(
            endpoint("reports", "https://reports.example.com/résumé")
        ));

        assertEquals("reports=\"https://reports.example.com/r%C3%A9sum%C3%A9\"",
            reportingEndpoints.toString());
    }

    @Test
    void makesADefensiveCopyOfTheEndpointCollection() {
        List<ReportingEndpoint> mutableEndpoints = new ArrayList<>();
        mutableEndpoints.add(endpoint("first", "/first"));
        ReportingEndpoints reportingEndpoints = new ReportingEndpoints(mutableEndpoints);

        mutableEndpoints.add(endpoint("second", "/second"));

        assertEquals("first=\"/first\"", reportingEndpoints.toString());
    }

    private static ReportingEndpoint endpoint(String name, String uri) {
        return new ReportingEndpointRecord(name, URI.create(uri));
    }
}
