package io.micronaut.security.docs.cspreport;

import io.micronaut.context.annotation.Property;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Property(name = "spec.name", value = "ApplicationCspReportHandlerTest")
@Property(name = "micronaut.security.csp.report-to.enabled", value = "true")
@Property(name = "micronaut.security.csp.report-to.group", value = "csp")
@Property(name = "micronaut.security.intercept-url-map[0].pattern", value = "/csp/report")
@Property(name = "micronaut.security.intercept-url-map[0].http-method", value = "POST")
@Property(name = "micronaut.security.intercept-url-map[0].access[0]", value = "isAnonymous()")
@MicronautTest
class ApplicationCspReportHandlerTest {
    private static final String REPORTS = """
        [{
          "type": "csp-violation",
          "age": 10,
          "url": "https://example.com/page",
          "user_agent": "Example Browser",
          "body": {
            "documentURL": "https://example.com/page",
            "blockedURL": "https://evil.example/script.js",
            "effectiveDirective": "script-src-elem",
            "originalPolicy": "script-src 'none'",
            "disposition": "enforce",
            "statusCode": 200
          }
        }]
        """;

    @Test
    void theReportEndpointAcceptsReportsWhenAHandlerExists(@Client("/") HttpClient httpClient) {
        HttpResponse<?> response = httpClient.toBlocking().exchange(
            HttpRequest.POST("/csp/report", REPORTS).contentType("application/reports+json"));

        assertEquals(HttpStatus.NO_CONTENT, response.getStatus());
    }
}
