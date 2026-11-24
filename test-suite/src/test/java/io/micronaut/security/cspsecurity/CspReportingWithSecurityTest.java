package io.micronaut.security.cspsecurity;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.csp.report.ContentSecurityPolicyReport;
import io.micronaut.security.csp.report.ContentSecurityPolicyReportHandler;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Report deliveries to the CSP report controller with Micronaut Security and the Fetch Metadata
 * module on the classpath, as documented in the Reporting API section of the CSP guide.
 */
class CspReportingWithSecurityTest {
    private static final String SPEC_NAME = "CspReportingWithSecurityTest";

    @Test
    void theSecurityRulesRejectAnonymousReportsUntilTheReportPathIsAllowed() {
        try (EmbeddedServer server = server(false);
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
                () -> httpClient.toBlocking().exchange(report("same-origin")));

            assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatus());
        }
    }

    @Test
    void anAllowedReportPathAcceptsSameOriginReportDeliveries() {
        try (EmbeddedServer server = server(true);
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            assertEquals(HttpStatus.NO_CONTENT, httpClient.toBlocking().exchange(report("same-origin")).getStatus());
        }
    }

    @Test
    void theFetchMetadataRulesRejectCrossSiteReportDeliveries() {
        try (EmbeddedServer server = server(true);
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
                () -> httpClient.toBlocking().exchange(report("cross-site")));

            assertEquals(HttpStatus.FORBIDDEN, exception.getStatus());
        }
    }

    private static EmbeddedServer server(boolean allowReports) {
        Map<String, Object> properties = new HashMap<>();
        properties.put("spec.name", SPEC_NAME);
        properties.put("micronaut.security.csp.report-to.enabled", true);
        if (allowReports) {
            properties.put("micronaut.security.intercept-url-map[0].pattern", "/csp/report");
            properties.put("micronaut.security.intercept-url-map[0].http-method", "POST");
            properties.put("micronaut.security.intercept-url-map[0].access", List.of("isAnonymous()"));
        }
        return ApplicationContext.run(EmbeddedServer.class, properties);
    }

    private static MutableHttpRequest<byte[]> report(String site) {
        return HttpRequest.POST("/csp/report", "[]".getBytes(StandardCharsets.UTF_8))
            .contentType(MediaType.of("application/reports+json"))
            .header(HttpHeaders.SEC_FETCH_SITE, site)
            .header(HttpHeaders.SEC_FETCH_MODE, "no-cors")
            .header(HttpHeaders.SEC_FETCH_DEST, "report");
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class NoOpReportHandler implements ContentSecurityPolicyReportHandler {
        @Override
        public void handle(List<ContentSecurityPolicyReport> reports, HttpRequest<?> request) {
        }
    }
}
