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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = "micronaut.security.csp.style-src.nonce", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csp.style-src.self", value = StringUtils.TRUE)
@Property(name = "micronaut.security.csp.style-src.values[0]", value = "https://cdn.jsdelivr.net")
@Property(name = "spec.name", value = "StyleSrcSelfTest")
@MicronautTest
class StyleSrcSelfTest {
    @Test
    void styleSelf(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpResponse<?> response = assertDoesNotThrow(() -> client.exchange(HttpRequest.GET("/cspexample")));
        ContentSecurityPolicy csp = ContentSecurityPolicy.of(response);
        assertNotNull(csp);
        ContentSecurityPolicyDirective directive = csp.styleSrc();
        assertNotNull(directive);
        assertEquals("'self' https://cdn.jsdelivr.net", directive.value());
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
