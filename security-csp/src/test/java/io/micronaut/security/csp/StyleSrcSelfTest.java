package io.micronaut.security.csp;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
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

@DisableCspDefaultsExceptStyle
@Property(name = "micronaut.security.csp.style-src[0]", value = "'self'")
@Property(name = "micronaut.security.csp.style-src[1]", value = "https://cdn.jsdelivr.net")
@Property(name = "spec.name", value = "StyleSrcSelfTest")
@MicronautTest
class StyleSrcSelfTest {
    @Test
    void styleSelf(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpResponse<?> response = assertDoesNotThrow(() -> client.exchange(HttpRequest.GET("/cspexample")));
        assertTrue(response.getHeaders().contains(CONTENT_SECURITY_POLICY));
        String csp = response.getHeaders().get(CONTENT_SECURITY_POLICY);
        assertEquals("style-src 'self' https://cdn.jsdelivr.net", csp);
    }

    @Requires(property = "spec.name", value = "StyleSrcSelfTest")
    @Controller("/cspexample")
    static class CspController {
        @Get
        @Status(HttpStatus.OK)
        void index() {
        }
    }
}
