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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
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
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Property(name = "spec.name", value = "ContentSecurityPolicyControllerTest")
@Property(name = "micronaut.security.csp.report-to.enabled", value = "true")
@MicronautTest
class ContentSecurityPolicyControllerTest {
    private static final String SPEC_NAME = "ContentSecurityPolicyControllerTest";

    @Inject
    ReportListener reportListener;

    @BeforeEach
    void resetTheListener() {
        reportListener.reset();
    }

    @Test
    void acceptsAndPublishesReportingApiBatch(@Client("/") HttpClient httpClient,
                                              ReportListener reportListener) {
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
                "subresourceURL": "https://example.com/worker.js",
                "hash": "sha256-example",
                "type": "subresource",
                "destination": "worker"
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
        assertNull(hashBody.documentUrl());
        assertEquals(ContentSecurityPolicyControllerConfigurationProperties.DEFAULT_PATH, reportListener.requestPath);
    }

    @Test
    void acceptsHashReportWithSpecificationExampleFieldNames(@Client("/") HttpClient httpClient,
                                                             ReportListener reportListener) {
        String json = """
            [{
              "type": "csp-hash",
              "age": 12,
              "url": "https://example.com/",
              "user_agent": "Example Browser",
              "body": {
                "document_url": "https://example.com/",
                "subresource_url": "https://example.com/main.js",
                "hash": "sha256-example",
                "type": "subresource",
                "destination": "script"
              }
            }]
            """;
        BlockingHttpClient client = httpClient.toBlocking();

        HttpResponse<?> response = client.exchange(reportRequest(json));

        assertEquals(HttpStatus.NO_CONTENT, response.status());
        ContentSecurityPolicyHashReportBody hashBody = assertInstanceOf(
            ContentSecurityPolicyHashReportBody.class,
            reportListener.reports.get(0).body()
        );
        assertEquals("https://example.com/", hashBody.documentUrl());
        assertEquals("https://example.com/main.js", hashBody.subresourceUrl());
    }

    @Test
    void rejectsHashReportWithoutHash(@Client("/") HttpClient httpClient,
                                      ReportListener reportListener) {
        String json = """
            [{
              "type": "csp-hash",
              "age": 12,
              "url": "https://example.com/",
              "user_agent": "Example Browser",
              "body": {
                "subresourceURL": "https://example.com/main.js",
                "type": "subresource",
                "destination": "script"
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
    void rejectsInvalidReportEnvelope(@Client("/") HttpClient httpClient,
                                      ReportListener reportListener) {
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
    void rejectsNullReportInBatch(@Client("/") HttpClient httpClient,
                                  ReportListener reportListener) {
        BlockingHttpClient client = httpClient.toBlocking();

        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(reportRequest("[null]")));

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatus());
        assertEquals(0, reportListener.reports.size());
    }

    @Test
    void skipsNonCspReportsDeliveredInTheSameBatch(@Client("/") HttpClient httpClient,
                                                   ReportListener reportListener) {
        String json = """
            [{
              "type": "deprecation",
              "age": 1,
              "url": "https://example.com/page",
              "user_agent": "Example Browser",
              "body": {"id": "x"}
            }, {
              "type": "csp-hash",
              "age": 2,
              "url": "https://example.com/page",
              "user_agent": "Example Browser",
              "body": {"hash": "sha256-example"}
            }]
            """;
        BlockingHttpClient client = httpClient.toBlocking();

        HttpResponse<?> response = client.exchange(reportRequest(json));

        assertEquals(HttpStatus.NO_CONTENT, response.getStatus());
        assertEquals(1, reportListener.reports.size());
        assertEquals(ContentSecurityPolicyReport.TYPE_CSP_HASH, reportListener.reports.get(0).type());
    }

    @Test
    void rejectsReportWithoutType(@Client("/") HttpClient httpClient,
                                  ReportListener reportListener) {
        String json = """
            [{
              "age": 1,
              "url": "https://example.com/page",
              "user_agent": "Example Browser",
              "body": {"hash": "sha256-example"}
            }]
            """;
        BlockingHttpClient client = httpClient.toBlocking();

        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(reportRequest(json)));

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatus());
        assertEquals(0, reportListener.reports.size());
    }

    @Test
    void rejectsMalformedJson(@Client("/") HttpClient httpClient,
                              ReportListener reportListener) {
        BlockingHttpClient client = httpClient.toBlocking();

        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(reportRequest("[{")));

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatus());
        assertEquals(0, reportListener.reports.size());
    }

    @Test
    void rejectsInvalidCspViolationBody(@Client("/") HttpClient httpClient,
                                        ReportListener reportListener) {
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

    @ParameterizedTest
    @ValueSource(strings = {
        "[{\"age\": \"x\"}]",
        "[{\"type\": \"csp-violation\", \"age\": 1, \"url\": \"https://example.com\", \"user_agent\": \"UA\", \"body\": {\"statusCode\": \"x\"}}]"
    })
    void doesNotRevealTheDecoderMessageInTheResponse(String json, @Client("/") HttpClient httpClient,
                                                     ReportListener reportListener) {
        BlockingHttpClient client = httpClient.toBlocking();

        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(reportRequest(json)));

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatus());
        String body = exception.getResponse().getBody(String.class).orElse("");
        assertFalse(body.contains("SerializedContentSecurityPolicyReport"), body);
        assertFalse(body.contains("java.lang"), body);
        assertFalse(body.contains("ContentSecurityPolicyViolationReportBody"), body);
        assertFalse(body.contains("Cannot deserialize"), body);
        assertEquals(0, reportListener.reports.size());
    }

    @ParameterizedTest
    @ValueSource(strings = {MediaType.APPLICATION_JSON, "application/csp-report", MediaType.TEXT_PLAIN})
    void requiresReportingApiMediaType(String contentType, @Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<byte[]> request = HttpRequest.POST(ContentSecurityPolicyControllerConfigurationProperties.DEFAULT_PATH,
                "[]".getBytes(StandardCharsets.UTF_8))
            .contentType(MediaType.of(contentType));

        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(request));

        assertEquals(HttpStatus.UNSUPPORTED_MEDIA_TYPE, exception.getStatus());
    }

    @Test
    void invokesTheHandlerOffTheEventLoop(@Client("/") HttpClient httpClient,
                                          ReportListener reportListener) {
        String json = """
            [{"type": "csp-hash", "age": 1, "url": "https://example.com/", "user_agent": "Example Browser",
              "body": {"document_url": "https://example.com/", "hash": "sha256-example"}}]
            """;

        httpClient.toBlocking().exchange(reportRequest(json));

        assertNotNull(reportListener.threadName);
        assertFalse(reportListener.threadName.toLowerCase(Locale.ROOT).contains("eventloop"),
            () -> "the handler may block, so it must not run on an event-loop thread: " + reportListener.threadName);
    }

    @Test
    void acceptsAnEmptyBatch(@Client("/") HttpClient httpClient,
                             ReportListener reportListener) {

        HttpResponse<?> response = httpClient.toBlocking().exchange(reportRequest("[]"));

        assertEquals(HttpStatus.NO_CONTENT, response.getStatus());
        assertEquals(0, reportListener.calls.get(), "the handler is not called without CSP reports");
    }

    @Test
    void doesNotCallTheHandlerForABatchWithoutCspReports(@Client("/") HttpClient httpClient,
                                                         ReportListener reportListener) {
        String json = """
            [{"type": "deprecation", "age": 1, "url": "https://example.com/page", "user_agent": "Example Browser", "body": {}}]
            """;

        HttpResponse<?> response = httpClient.toBlocking().exchange(reportRequest(json));

        assertEquals(HttpStatus.NO_CONTENT, response.getStatus());
        assertEquals(0, reportListener.calls.get());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "null"})
    void rejectsABodyWithoutABatch(String json, @Client("/") HttpClient httpClient) {
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> httpClient.toBlocking().exchange(reportRequest(json)));

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatus());
        assertEquals(0, reportListener.calls.get());
    }

    @Test
    void decodesTheBodyOffTheEventLoop(@Client("/") HttpClient httpClient) {
        Logger logger = (Logger) LoggerFactory.getLogger(ContentSecurityPolicyReportBodyReader.class);
        Level level = logger.getLevel();
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(Level.DEBUG);
        try {
            assertThrows(HttpClientResponseException.class, () -> httpClient.toBlocking().exchange(reportRequest("[{")));
        } finally {
            logger.detachAppender(appender);
            logger.setLevel(level);
        }

        assertEquals(1, appender.list.size(), "the reader logs the rejection");
        String thread = appender.list.get(0).getThreadName();
        assertFalse(thread.toLowerCase(Locale.ROOT).contains("eventloop"),
            () -> "an anonymous body must not be parsed on an event-loop thread: " + thread);
    }

    private static HttpRequest<byte[]> reportRequest(String json) {
        return HttpRequest.POST(ContentSecurityPolicyControllerConfigurationProperties.DEFAULT_PATH, json.getBytes(StandardCharsets.UTF_8))
            .contentType(MediaType.of(ContentSecurityPolicyController.APPLICATION_REPORTS_JSON));
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class ReportListener implements ContentSecurityPolicyReportHandler {
        private final List<ContentSecurityPolicyReport> reports = new CopyOnWriteArrayList<>();
        private final AtomicInteger calls = new AtomicInteger();
        private volatile String requestPath;
        private volatile String threadName;

        void reset() {
            reports.clear();
            calls.set(0);
            requestPath = null;
            threadName = null;
        }

        @Override
        public void handle(List<ContentSecurityPolicyReport> reports, HttpRequest<?> request) {
            this.reports.addAll(reports);
            calls.incrementAndGet();
            requestPath = request.getPath();
            threadName = Thread.currentThread().getName();
        }
    }
}
