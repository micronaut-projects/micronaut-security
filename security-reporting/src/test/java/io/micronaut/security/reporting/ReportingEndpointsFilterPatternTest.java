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

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Status;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

@Property(name = "spec.name", value = ReportingEndpointsFilterPatternTest.SPEC_NAME)
@Property(name = ReportingEndpointConfiguration.PREFIX + ".reports.url", value = "/reports")
@Property(name = "micronaut.security.reporting.filter.pattern", value = "/included/**")
@MicronautTest
class ReportingEndpointsFilterPatternTest {
    static final String SPEC_NAME = "ReportingEndpointsFilterPatternTest";

    @Test
    void addsHeaderOnlyToMatchingPaths(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();

        HttpResponse<?> included = client.exchange(HttpRequest.GET("/included/resource"));
        HttpResponse<?> excluded = client.exchange(HttpRequest.GET("/excluded/resource"));

        assertEquals("reports=\"/reports\"", included.header(ReportingEndpoints.HEADER_NAME));
        assertNull(excluded.header(ReportingEndpoints.HEADER_NAME));
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller
    static final class TestController {
        @Get("/included/resource")
        @Status(HttpStatus.OK)
        void included() {
        }

        @Get("/excluded/resource")
        @Status(HttpStatus.OK)
        void excluded() {
        }
    }
}
