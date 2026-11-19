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
package io.micronaut.security.csp.report;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Status;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.csp.conf.reportto.ReportToConfigurationProperties;
import io.micronaut.security.reporting.ReportingEndpoints;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Property(name = "spec.name", value = ReportToContextPathTest.SPEC_NAME)
@Property(name = "micronaut.server.context-path", value = "/app")
@Property(name = ReportToConfigurationProperties.PREFIX + ".enabled", value = "true")
@MicronautTest
class ReportToContextPathTest {
    static final String SPEC_NAME = "ReportToContextPathTest";

    @Test
    void advertisedReportingEndpointIncludesTheServerContextPath(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();

        HttpResponse<?> response = client.exchange(HttpRequest.GET("/app/report-to-context-path"));

        assertEquals("csp=\"/app/csp/report\"", response.header(ReportingEndpoints.HEADER_NAME));

        HttpResponse<?> reportResponse = client.exchange(HttpRequest.POST("/app/csp/report",
                "[]".getBytes(StandardCharsets.UTF_8))
            .contentType(MediaType.of(ContentSecurityPolicyController.APPLICATION_REPORTS_JSON)));
        assertEquals(HttpStatus.NO_CONTENT, reportResponse.getStatus());
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static final class TestReportHandler implements ContentSecurityPolicyReportHandler {
        @Override
        public void handle(List<ContentSecurityPolicyReport> reports, HttpRequest<?> request) {
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller("/report-to-context-path")
    static final class TestController {
        @Get
        @Status(HttpStatus.OK)
        void index() {
        }
    }
}
