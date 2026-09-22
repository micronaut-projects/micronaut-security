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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = "spec.name", value = "ScriptSrcDefaultsToTest")
@MicronautTest
class ScriptSrcDefaultsToTest {
    @Test
    void scriptSrcDefaultsToNone(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpResponse<?> response = assertDoesNotThrow(() -> client.exchange(HttpRequest.GET("/cspexample")));
        ContentSecurityPolicy csp = ContentSecurityPolicy.of(response);
        assertNotNull(csp);
        ContentSecurityPolicyDirective directive = csp.scriptSrc();
        assertNotNull(directive);
        assertTrue(directive.isNone());
    }

    @Requires(property = "spec.name", value = "ScriptSrcDefaultsToTest")
    @Controller("/cspexample")
    static class CspController {
        @Get
        @Status(HttpStatus.OK)
        void index() {
        }
    }
}
