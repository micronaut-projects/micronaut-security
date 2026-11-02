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
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Status;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.csp.ContentSecurityPolicy;
import io.micronaut.security.csp.ContentSecurityPolicyDirective;
import io.micronaut.security.csp.ContentSecurityPolicyGenerator;
import io.micronaut.security.csp.conf.reportTo.ReportToConfigurationProperties;
import io.micronaut.security.reporting.ReportingEndpoints;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Property(name = "spec.name", value = ReportToTest.SPEC_NAME)
@Property(name = ReportToConfigurationProperties.PREFIX + ".enabled", value = "true")
@Property(name = ReportToConfigurationProperties.PREFIX + ".group", value = "security-csp")
@Property(name = ContentSecurityPolicyControllerConfigurationProperties.PREFIX + ".path", value = ReportToTest.REPORT_PATH)
@MicronautTest
class ReportToTest {
    static final String SPEC_NAME = "ReportToTest";
    static final String REPORT_PATH = "/custom-csp-report";

    @Test
    void addsReportToDirectiveAndReportingEndpointsHeader(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();

        HttpResponse<?> response = client.exchange(HttpRequest.GET("/report-to-example"));

        ContentSecurityPolicy policy = ContentSecurityPolicy.of(response);
        assertNotNull(policy);
        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.REPORT_TO, "security-csp"),
            policy.reportTo());
        assertEquals("security-csp=\"/custom-csp-report\"",
            response.header(ReportingEndpoints.HEADER_NAME));
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static final class TestReportHandler implements ContentSecurityPolicyReportHandler {
        @Override
        public void handle(List<ContentSecurityPolicyReport> reports, HttpRequest<?> request) {
            // The response-header test needs the handler bean to activate the reporting endpoint.
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller("/report-to-example")
    static final class TestController {
        @Get
        @Status(HttpStatus.OK)
        void index() {
        }
    }
}
