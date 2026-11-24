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
import io.micronaut.security.reporting.ReportingEndpointProvider;
import io.micronaut.security.reporting.ReportingEndpoints;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Lives outside {@code io.micronaut.security.csp} so that the package-level requirements of the
 * module do not disable the test beans themselves.
 */
class CspTogglesTest {
    private static final String SPEC_NAME = "CspTogglesTest";

    @ParameterizedTest(name = "{0}={1} writes the header: {2}")
    @CsvSource({
        "micronaut.security.csp.enabled, true, true",
        "micronaut.security.csp.enabled, TRUE, true",
        "micronaut.security.csp.enabled, True, true",
        "micronaut.security.csp.enabled, yes, true",
        "micronaut.security.csp.enabled, on, true",
        "micronaut.security.csp.enabled, false, false",
        "micronaut.security.csp.enabled, FALSE, false",
        "micronaut.security.csp.enabled, no, false",
        "micronaut.security.csp.enabled, off, false",
        "micronaut.security.csp.enabled, Off, false",
        "micronaut.security.csp.enabled, ' false ', false",
        "micronaut.security.csp.enabled, ture, true",
        "micronaut.security.csp.enabled, maybe, true",
        "micronaut.security.csp.filter.enabled, TRUE, true",
        "micronaut.security.csp.filter.enabled, yes, true",
        "micronaut.security.csp.filter.enabled, false, false",
        "micronaut.security.csp.filter.enabled, FALSE, false",
        "micronaut.security.csp.filter.enabled, off, false",
        "micronaut.security.csp.filter.enabled, maybe, true"
    })
    void enabledTogglesAcceptEverySpellingOfABoolean(String property, String value, boolean header) {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", SPEC_NAME, property, value));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/csp-toggles"), String.class);

            assertEquals(header, ContentSecurityPolicy.of(response) != null);
        }
    }

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

    @Test
    void aReportHandlerAloneDoesNotAddTheReportingApiFilter() throws ClassNotFoundException {
        Class<?> reportingEndpointsFilter = Class.forName("io.micronaut.security.reporting.ReportingEndpointsFilter");
        try (ApplicationContext context = ApplicationContext.run(Map.of("spec.name", SPEC_NAME))) {
            assertTrue(context.getBeansOfType(ReportingEndpointProvider.class).isEmpty(), "report-to is disabled, so nothing is advertised");
            assertFalse(context.containsBean(reportingEndpointsFilter), "no filter may run on every request to write nothing");
        }
        try (ApplicationContext context = ApplicationContext.run(Map.of(
                "spec.name", SPEC_NAME,
                "micronaut.security.csp.report-to.enabled", true))) {
            assertEquals(1, context.getBeansOfType(ReportingEndpointProvider.class).size());
            assertTrue(context.containsBean(reportingEndpointsFilter));
        }
    }

    @ParameterizedTest(name = "controller.enabled={0}")
    @ValueSource(strings = {"false", "FALSE", "off", "No"})
    void everySpellingOfFalseUnregistersTheReportController(String value) {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", SPEC_NAME,
                "micronaut.security.csp.report-to.enabled", true,
                "micronaut.security.csp.report-to.controller.enabled", value));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();

            HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
                () -> client.exchange(reportRequest()));

            assertEquals(HttpStatus.NOT_FOUND, exception.getStatus());
            assertNull(exception.getResponse().header(ReportingEndpoints.HEADER_NAME));
        }
    }

    @ParameterizedTest(name = "report-to.enabled={0}")
    @ValueSource(strings = {"true", "TRUE", "yes", "On"})
    void everySpellingOfTrueRegistersTheEndpointThatTheReportToDirectiveNames(String value) {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", SPEC_NAME,
                "micronaut.security.csp.report-to.enabled", value));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();

            HttpResponse<String> page = client.exchange(HttpRequest.GET("/csp-toggles"), String.class);
            assertEquals("report-to csp", ContentSecurityPolicy.of(page).reportTo().toHeaderValue());
            assertEquals("csp=\"/csp/report\"", page.header(ReportingEndpoints.HEADER_NAME));
            assertEquals(HttpStatus.NO_CONTENT, client.exchange(reportRequest()).getStatus());
        }
    }

    @Test
    void aReportingEndpointConfiguredWithTheGroupNameReceivesTheReports() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", SPEC_NAME,
                "micronaut.security.csp.report-to.enabled", true,
                "micronaut.security.reporting-endpoints.csp.url", "https://reports.example.com/csp"));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            HttpResponse<String> page = httpClient.toBlocking().exchange(HttpRequest.GET("/csp-toggles"), String.class);

            assertEquals("csp=\"https://reports.example.com/csp\"", page.header(ReportingEndpoints.HEADER_NAME),
                "the endpoint is declared once, by the configuration");
        }
    }

    @ParameterizedTest(name = "controller.path={0}")
    @ValueSource(strings = {"", "csp/report", "//evil.example/csp"})
    void anInvalidReportControllerPathFailsStartup(String path) {
        assertThrows(RuntimeException.class, () -> ApplicationContext.run(EmbeddedServer.class, Map.of(
            "spec.name", SPEC_NAME,
            "micronaut.security.csp.report-to.enabled", true,
            "micronaut.security.csp.report-to.controller.path", path)).close());
    }

    @Test
    void anInvalidReportControllerPathFailsStartupNextToAConfiguredReportingEndpoint() {
        assertThrows(RuntimeException.class, () -> ApplicationContext.run(EmbeddedServer.class, Map.of(
            "spec.name", SPEC_NAME,
            "micronaut.security.csp.report-to.enabled", true,
            "micronaut.security.csp.report-to.controller.path", "csp/report",
            "micronaut.security.reporting-endpoints.other.url", "https://reports.example.com/other")).close());
    }

    private static HttpRequest<byte[]> reportRequest() {
        return HttpRequest.POST("/csp/report", "[]".getBytes(StandardCharsets.UTF_8))
            .contentType(MediaType.of("application/reports+json"));
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
