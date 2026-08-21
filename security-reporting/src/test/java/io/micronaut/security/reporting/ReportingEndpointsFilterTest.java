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
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Status;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Property(name = "spec.name", value = ReportingEndpointsFilterTest.SPEC_NAME)
@Property(name = ReportingEndpointConfiguration.PREFIX + ".csp.url", value = "/csp/report")
@Property(name = ReportingEndpointConfiguration.PREFIX + ".network.url", value = "https://example.com/network-reports")
@MicronautTest
class ReportingEndpointsFilterTest {
    static final String SPEC_NAME = "ReportingEndpointsFilterTest";
    private static final String CUSTOM_HEADER = "application=\"/application-reports\"";

    @Test
    void addsConfiguredAndRequestSpecificReportingEndpoints(@Client("/") HttpClient httpClient) {
        HttpResponse<?> response = httpClient.toBlocking().exchange(HttpRequest.GET("/reporting-endpoints"));

        assertEquals("csp=\"/csp/report\", network=\"https://example.com/network-reports\", " +
                "request=\"/reporting-endpoints/reports\"",
            response.header(ReportingEndpoints.HEADER_NAME));
    }

    @Test
    void doesNotOverwriteApplicationHeader(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();

        HttpResponse<?> response = client.exchange(HttpRequest.GET("/reporting-endpoints/custom"));

        assertEquals(CUSTOM_HEADER, response.header(ReportingEndpoints.HEADER_NAME));
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller("/reporting-endpoints")
    static final class TestController {
        @Get
        @Status(HttpStatus.OK)
        void index() {
        }

        @Get("/custom")
        MutableHttpResponse<?> custom() {
            return HttpResponse.ok().header(ReportingEndpoints.HEADER_NAME, CUSTOM_HEADER);
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static final class TestReportingEndpointProvider implements ReportingEndpointProvider {
        @Override
        public ReportingEndpoint reportingEndpoint(HttpRequest<?> request) {
            return new ReportingEndpointRecord("request", URI.create(request.getPath() + "/reports"));
        }
    }
}
