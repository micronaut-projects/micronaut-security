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

import io.micronaut.context.annotation.Requires;
import io.micronaut.context.annotation.Property;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Property(name = "spec.name", value = "ContentSecurityPolicyControllerTest")
@MicronautTest
class ContentSecurityPolicyControllerTest {
    private static final String SPEC_NAME = "ContentSecurityPolicyControllerTest";

    @Test
    void acceptsAndPublishesReportingApiBatch(@Client("/") HttpClient httpClient,
                                              ReportListener reportListener) {
        reportListener.reports.clear();
        String json = """
            [{
              "type": "csp-violation",
              "age": 10,
              "url": "https://example.com/page",
              "user_agent": "Example Browser",
              "body": {
                "documentURL": "https://example.com/page",
                "referrer": "https://example.com/",
                "blockedURL": "https://evil.example/script.js",
                "effectiveDirective": "script-src-elem",
                "originalPolicy": "script-src 'none'",
                "sourceFile": "https://example.com/app.js",
                "sample": "alert('example')",
                "disposition": "enforce",
                "statusCode": 200,
                "lineNumber": 12,
                "columnNumber": 4
              }
            }, {
              "type": "csp-hash",
              "age": 20,
              "url": "https://example.com/worker.js",
              "user_agent": "Example Browser",
              "body": {
                "document_url": "https://example.com/",
                "subresource_url": "https://example.com/worker.js",
                "hash": "sha256-example",
                "destination": "worker",
                "type": "subresource"
              }
            }]
            """;
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<byte[]> request = HttpRequest.POST(ContentSecurityPolicyControllerConfigurationProperties.DEFAULT_PATH,
                json.getBytes(StandardCharsets.UTF_8))
            .contentType(MediaType.of(ContentSecurityPolicyController.APPLICATION_REPORTS_JSON));

        HttpResponse<?> response = client.exchange(request);

        assertEquals(HttpStatus.NO_CONTENT, response.status());
        assertEquals(2, reportListener.reports.size());
        ContentSecurityPolicyReport report = reportListener.reports.get(0);
        assertEquals(10L, report.age());
        assertEquals("csp-violation", report.type());
        assertEquals("https://example.com/page", report.url());
        assertEquals("Example Browser", report.userAgent());
        assertNotNull(report.body());
        ContentSecurityPolicyViolationReportBody violationBody = assertInstanceOf(
            ContentSecurityPolicyViolationReportBody.class,
            report.body()
        );
        assertEquals("script-src-elem", violationBody.effectiveDirective());
        assertEquals(ContentSecurityPolicyReportDisposition.ENFORCE, violationBody.disposition());
        ContentSecurityPolicyHashReportBody hashBody = assertInstanceOf(
            ContentSecurityPolicyHashReportBody.class,
            reportListener.reports.get(1).body()
        );
        assertEquals("sha256-example", hashBody.hash());
        assertEquals("https://example.com/worker.js", hashBody.subresourceUrl());
        assertEquals(ContentSecurityPolicyControllerConfigurationProperties.DEFAULT_PATH, reportListener.requestPath);
    }

    @Test
    void rejectsInvalidReportEnvelope(@Client("/") HttpClient httpClient,
                                      ReportListener reportListener) {
        reportListener.reports.clear();
        String json = """
            [{
              "type": "csp-violation",
              "age": -1,
              "url": "https://example.com/page",
              "user_agent": "Example Browser",
              "body": {
                "documentURL": "https://example.com/page",
                "effectiveDirective": "script-src",
                "originalPolicy": "script-src 'none'",
                "disposition": "enforce",
                "statusCode": 200
              }
            }]
            """;
        BlockingHttpClient client = httpClient.toBlocking();

        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(reportRequest(json)));

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatus());
        assertEquals(0, reportListener.reports.size());
    }

    @Test
    void rejectsCspReportWithoutItsSpecifiedBody(@Client("/") HttpClient httpClient,
                                                  ReportListener reportListener) {
        reportListener.reports.clear();
        String json = """
            [{
              "type": "csp-violation",
              "age": 1,
              "url": "https://example.com/page",
              "user_agent": "Example Browser",
              "body": null
            }]
            """;
        BlockingHttpClient client = httpClient.toBlocking();

        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(reportRequest(json)));

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatus());
        assertEquals(0, reportListener.reports.size());
    }

    @Test
    void rejectsInvalidCspViolationBody(@Client("/") HttpClient httpClient,
                                        ReportListener reportListener) {
        reportListener.reports.clear();
        String json = """
            [{
              "type": "csp-violation",
              "age": 1,
              "url": "https://example.com/page",
              "user_agent": "Example Browser",
              "body": {
                "effectiveDirective": "script-src",
                "originalPolicy": "script-src 'none'",
                "disposition": "enforce",
                "statusCode": 200
              }
            }]
            """;
        BlockingHttpClient client = httpClient.toBlocking();

        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(reportRequest(json)));

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatus());
        assertEquals(0, reportListener.reports.size());
    }

    @Test
    void requiresReportingApiMediaType(@Client("/") HttpClient httpClient) {
        String json = "[]";
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<byte[]> request = HttpRequest.POST(ContentSecurityPolicyControllerConfigurationProperties.DEFAULT_PATH,
                json.getBytes(StandardCharsets.UTF_8))
            .contentType(MediaType.APPLICATION_JSON_TYPE);

        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(request));

        assertEquals(HttpStatus.UNSUPPORTED_MEDIA_TYPE, exception.getStatus());
    }

    private static HttpRequest<byte[]> reportRequest(String json) {
        return HttpRequest.POST(ContentSecurityPolicyControllerConfigurationProperties.DEFAULT_PATH, json.getBytes(StandardCharsets.UTF_8))
            .contentType(MediaType.of(ContentSecurityPolicyController.APPLICATION_REPORTS_JSON));
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class ReportListener implements ContentSecurityPolicyReportHandler {
        private final List<ContentSecurityPolicyReport> reports = new CopyOnWriteArrayList<>();
        private volatile String requestPath;

        @Override
        public void handle(List<ContentSecurityPolicyReport> reports, HttpRequest<?> request) {
            this.reports.addAll(reports);
            requestPath = request.getPath();
        }
    }
}
