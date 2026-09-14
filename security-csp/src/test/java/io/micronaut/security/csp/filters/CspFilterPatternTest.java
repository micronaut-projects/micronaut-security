package io.micronaut.security.csp.filters;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
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
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

@Property(name = "micronaut.security.csp.filter.pattern", value = "/foo/**")
@Property(name = "spec.name", value = "CspFilterPatternTest")
@MicronautTest
class CspFilterPatternTest {
    @Test
    void cspFilterPattern(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpResponse<?> response = assertDoesNotThrow(() -> client.exchange(HttpRequest.GET("/cspexample")));
        ContentSecurityPolicy csp = ContentSecurityPolicy.of(response);
        assertNull(csp, "CSP filter pattern should not match request path");
    }

    @Requires(property = "spec.name", value = "CspFilterPatternTest")
    @Controller("/cspexample")
    static class CspController {
        @Get
        @Status(HttpStatus.OK)
        void index() {
        }
    }
}
