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

import static io.micronaut.security.csp.CspHeaders.CONTENT_SECURITY_POLICY;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisableCspDefaults
@Property(name = "micronaut.security.csp.script-src-urls[0]", value = "https://cdn.jsdelivr.net")
@Property(name = "micronaut.security.csp.script-src-hashes[0]", value = "sha256-Eco45CPSfPGYCeRWuzpCqnc/toI8+r22Lkjfm5XoezE=")
@Property(name = "micronaut.security.csp.script-src-self", value = StringUtils.TRUE)
@Property(name = "spec.name", value = "ScriptSrcSelfUrlsTest")
@MicronautTest
class ScriptSrcSelfUrlsTest {

    @Test
    void scriptSrcUrls(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpResponse<?> response = assertDoesNotThrow(() -> client.exchange(HttpRequest.GET("/cspexample")));
        assertTrue(response.getHeaders().contains(CONTENT_SECURITY_POLICY));
        String csp = response.getHeaders().get(CONTENT_SECURITY_POLICY);
        String expected = "script-src 'self' 'sha256-Eco45CPSfPGYCeRWuzpCqnc/toI8+r22Lkjfm5XoezE=' https://cdn.jsdelivr.net";
        assertEquals(expected, csp);
    }

    @Requires(property = "spec.name", value = "ScriptSrcSelfUrlsTest")
    @Controller("/cspexample")
    static class CspController {
        @Get
        @Status(HttpStatus.OK)
        void index() {

        }
    }
}
