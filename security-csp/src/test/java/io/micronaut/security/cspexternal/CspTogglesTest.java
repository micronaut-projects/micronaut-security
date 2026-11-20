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
package io.micronaut.security.cspexternal;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.csp.ContentSecurityPolicy;
import io.micronaut.security.csp.report.ContentSecurityPolicyReport;
import io.micronaut.security.csp.report.ContentSecurityPolicyReportHandler;
import io.micronaut.security.reporting.ReportingEndpoints;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Lives outside {@code io.micronaut.security.csp} so that the package-level requirements of the
 * module do not disable the test beans themselves.
 */
class CspTogglesTest {
    private static final String SPEC_NAME = "CspTogglesTest";

    @Test
    void disablingTheFilterRemovesTheHeader() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", SPEC_NAME,
                "micronaut.security.csp.filter.enabled", false));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/csp-toggles"), String.class);

            assertNull(ContentSecurityPolicy.of(response));
        }
    }

    @Test
    void enablingTheFilterExplicitlyKeepsTheHeader() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", SPEC_NAME,
                "micronaut.security.csp.filter.enabled", true));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/csp-toggles"), String.class);

            assertNotNull(ContentSecurityPolicy.of(response));
        }
    }

    @Test
    void disablingTheReportControllerUnregistersItEvenWithAHandler() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", SPEC_NAME,
                "micronaut.security.csp.report-to.enabled", true,
                "micronaut.security.csp.report-to.controller.enabled", false));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            HttpRequest<byte[]> request = HttpRequest.POST("/csp/report", "[]".getBytes(StandardCharsets.UTF_8))
                .contentType(MediaType.of("application/reports+json"));

            HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
                () -> client.exchange(request));

            assertEquals(HttpStatus.NOT_FOUND, exception.getStatus());
            assertNull(exception.getResponse().header(ReportingEndpoints.HEADER_NAME));
        }
    }

    @Test
    void reportControllerIsNotRegisteredWhenReportToIsDisabled() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", SPEC_NAME));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            HttpRequest<byte[]> request = HttpRequest.POST("/csp/report", "[]".getBytes(StandardCharsets.UTF_8))
                .contentType(MediaType.of("application/reports+json"));

            HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
                () -> client.exchange(request));

            assertEquals(HttpStatus.NOT_FOUND, exception.getStatus(), "a handler bean alone must not open the report route");
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller("/csp-toggles")
    static class TogglesController {
        @Get
        @Produces(MediaType.TEXT_PLAIN)
        String index() {
            return "ok";
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class NoOpReportHandler implements ContentSecurityPolicyReportHandler {
        @Override
        public void handle(List<ContentSecurityPolicyReport> reports, HttpRequest<?> request) {
        }
    }
}
