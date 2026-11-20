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
package io.micronaut.security.csp;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * End-to-end check of {@code micronaut.security.csp.report-only}: the bound property switches the
 * response header to {@code Content-Security-Policy-Report-Only}.
 */
@Property(name = "spec.name", value = "ReportOnlyHttpTest")
@Property(name = "micronaut.security.csp.report-only", value = StringUtils.TRUE)
@MicronautTest
class ReportOnlyHttpTest {

    @Test
    void reportOnlyModeWritesOnlyTheReportOnlyHeader(@Client("/") HttpClient httpClient) {
        HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/report-only"), String.class);

        assertEquals(DefaultPolicyHttpTest.DEFAULT_POLICY, response.header(HttpHeaders.CONTENT_SECURITY_POLICY_REPORT_ONLY));
        assertNull(response.header(HttpHeaders.CONTENT_SECURITY_POLICY), "report-only mode must not also enforce the policy");
    }

    @Test
    void anEnforcingHeaderSetByTheApplicationDoesNotSuppressTheReportOnlyHeader(@Client("/") HttpClient httpClient) {
        HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/report-only/enforced"), String.class);

        assertEquals("default-src 'self'", response.header(HttpHeaders.CONTENT_SECURITY_POLICY), "the application's header is kept");
        assertEquals(DefaultPolicyHttpTest.DEFAULT_POLICY, response.header(HttpHeaders.CONTENT_SECURITY_POLICY_REPORT_ONLY),
            "only a Report-Only header set by the application suppresses the module's Report-Only header");
    }

    @Test
    void aReportOnlyHeaderSetByTheApplicationIsKept(@Client("/") HttpClient httpClient) {
        HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/report-only/own"), String.class);

        assertEquals("default-src 'self'", response.header(HttpHeaders.CONTENT_SECURITY_POLICY_REPORT_ONLY));
        assertNull(response.header(HttpHeaders.CONTENT_SECURITY_POLICY));
    }

    @Requires(property = "spec.name", value = "ReportOnlyHttpTest")
    @Controller("/report-only")
    static class ReportOnlyController {
        @Get
        String index() {
            return "ok";
        }

        @Get("/enforced")
        HttpResponse<String> enforced() {
            return HttpResponse.ok("ok").header(HttpHeaders.CONTENT_SECURITY_POLICY, "default-src 'self'");
        }

        @Get("/own")
        HttpResponse<String> own() {
            return HttpResponse.ok("ok").header(HttpHeaders.CONTENT_SECURITY_POLICY_REPORT_ONLY, "default-src 'self'");
        }
    }
}
