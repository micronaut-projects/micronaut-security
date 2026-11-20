package io.micronaut.security.graal;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.csp.ContentSecurityPolicy;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;
import io.micronaut.security.csp.report.ContentSecurityPolicyReport;
import io.micronaut.security.csp.report.ContentSecurityPolicyReportHandler;
import io.micronaut.security.csp.report.ContentSecurityPolicyViolationReportBody;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Smoke test of the CSP module in a native image: the policy header, the request nonce, and the
 * Reporting API endpoint with its body reader and serde-decoded report types.
 */
@Property(name = "spec.name", value = "ContentSecurityPolicyTest")
@Property(name = "micronaut.security.csp.script-src.nonce", value = StringUtils.TRUE)
@Property(name = "micronaut.security.csp.report-to.enabled", value = StringUtils.TRUE)
@Property(name = "micronaut.security.intercept-url-map[0].pattern", value = "/csp/report")
@Property(name = "micronaut.security.intercept-url-map[0].http-method", value = "POST")
@Property(name = "micronaut.security.intercept-url-map[0].access[0]", value = SecurityRule.IS_ANONYMOUS)
@MicronautTest
class ContentSecurityPolicyTest {
    private static final String REPORTS = """
        [{
          "type": "csp-violation",
          "age": 10,
          "url": "https://example.com/page",
          "user_agent": "Example Browser",
          "body": {
            "documentURL": "https://example.com/page",
            "blockedURL": "inline",
            "effectiveDirective": "script-src-elem",
            "originalPolicy": "script-src 'none'; report-to csp",
            "disposition": "enforce",
            "statusCode": 200
          }
        }]
        """;

    @Inject
    @Client("/")
    HttpClient httpClient;

    @Inject
    RecordingReportHandler reportHandler;

    @Test
    void writesThePolicyWithTheRequestNonce() {
        HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/csp-native"), String.class);

        ContentSecurityPolicy policy = ContentSecurityPolicy.of(response);
        assertNotNull(policy);
        assertEquals("'none'", policy.defaultSrc().value());
        assertEquals("'nonce-" + response.body() + "'", policy.scriptSrc().value());
        assertEquals("csp", policy.reportTo().value());
    }

    @Test
    void decodesAndHandlesAReport() {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<byte[]> request = HttpRequest.POST("/csp/report", REPORTS.getBytes(StandardCharsets.UTF_8))
            .contentType(MediaType.of("application/reports+json"));

        HttpResponse<?> response = client.exchange(request);

        assertEquals(HttpStatus.NO_CONTENT, response.getStatus());
        assertEquals(1, reportHandler.reports.size());
        ContentSecurityPolicyViolationReportBody body = assertInstanceOf(ContentSecurityPolicyViolationReportBody.class,
            reportHandler.reports.get(0).body());
        assertEquals("script-src-elem", body.effectiveDirective());
    }

    @Requires(property = "spec.name", value = "ContentSecurityPolicyTest")
    @Controller("/csp-native")
    static class NonceController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String index(HttpRequest<?> request) {
            return request.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, String.class).orElse("no nonce");
        }
    }

    @Requires(property = "spec.name", value = "ContentSecurityPolicyTest")
    @Singleton
    static class RecordingReportHandler implements ContentSecurityPolicyReportHandler {
        final List<ContentSecurityPolicyReport> reports = new CopyOnWriteArrayList<>();

        @Override
        public void handle(List<ContentSecurityPolicyReport> reports, HttpRequest<?> request) {
            this.reports.addAll(reports);
        }
    }
}
