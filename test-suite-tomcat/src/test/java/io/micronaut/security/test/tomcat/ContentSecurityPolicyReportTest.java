package io.micronaut.security.test.tomcat;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.csp.report.ContentSecurityPolicyReport;
import io.micronaut.security.csp.report.ContentSecurityPolicyReportHandler;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The report controller reads the request body as a stream; this test proves that it also works on
 * the servlet runtime.
 */
@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "pleaseChangeThisSecretForANewOne")
@Property(name = "micronaut.security.csp.report-to.enabled", value = StringUtils.TRUE)
@Property(name = "micronaut.security.intercept-url-map[0].pattern", value = "/csp/report")
@Property(name = "micronaut.security.intercept-url-map[0].http-method", value = "POST")
@Property(name = "micronaut.security.intercept-url-map[0].access[0]", value = "isAnonymous()")
@Property(name = "spec.name", value = "ContentSecurityPolicyReportTest")
@MicronautTest
class ContentSecurityPolicyReportTest {
    private static final String REPORT = """
        [{"type": "csp-hash", "age": 1, "url": "https://example.com/", "user_agent": "Example Browser",
          "body": {"document_url": "https://example.com/", "hash": "sha256-example"}}]
        """;

    @Inject
    @Client("/")
    HttpClient httpClient;

    @Inject
    Reports reports;

    @Test
    void tomcatDeliversAReportBatchToTheHandler() {
        reports.received.clear();

        assertEquals(HttpStatus.NO_CONTENT, httpClient.toBlocking().exchange(request(REPORT)).getStatus());
        assertEquals(1, reports.received.size());
        assertEquals("sha256-example", reports.received.get(0).body() instanceof io.micronaut.security.csp.report.ContentSecurityPolicyHashReportBody hash
            ? hash.hash() : null);
    }

    @Test
    void tomcatRejectsAnInvalidBatch() {
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> httpClient.toBlocking().exchange(request("[{")));

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatus());
    }

    private static HttpRequest<byte[]> request(String json) {
        return HttpRequest.POST("/csp/report", json.getBytes(StandardCharsets.UTF_8))
            .contentType(MediaType.of("application/reports+json"));
    }

    @Requires(property = "spec.name", value = "ContentSecurityPolicyReportTest")
    @Singleton
    static class Reports implements ContentSecurityPolicyReportHandler {
        private final List<ContentSecurityPolicyReport> received = new CopyOnWriteArrayList<>();

        @Override
        public void handle(List<ContentSecurityPolicyReport> reports, HttpRequest<?> request) {
            received.addAll(reports);
        }
    }
}
