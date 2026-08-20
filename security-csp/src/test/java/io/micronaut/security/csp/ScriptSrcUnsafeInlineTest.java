package io.micronaut.security.csp;

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
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import static io.micronaut.security.csp.ContentSecurityPolicyHeaders.CONTENT_SECURITY_POLICY;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisableCspDefaults
@Property(name = "micronaut.security.csp.script-src-unsafe-inline", value = StringUtils.TRUE)
@Property(name = "spec.name", value = "ScriptSrcUnsafeInlineTest")
@MicronautTest
class ScriptSrcUnsafeInlineTest {
    @Test
    void scriptSelf(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpResponse<?> response = assertDoesNotThrow(() -> client.exchange(HttpRequest.GET("/cspexample")));
        assertTrue(response.getHeaders().contains(CONTENT_SECURITY_POLICY));
        String csp = response.getHeaders().get(CONTENT_SECURITY_POLICY);
        assertEquals("script-src 'unsafe-inline'", csp);
    }

    @Requires(property = "spec.name", value = "ScriptSrcUnsafeInlineTest")
    @Controller("/cspexample")
    static class CspController {
        @Get
        @Status(HttpStatus.OK)
        void index() {
        }
    }
}
