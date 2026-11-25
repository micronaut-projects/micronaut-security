package io.micronaut.security.docs.cspgenerator;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Property(name = "spec.name", value = "ApplicationContentSecurityPolicyGeneratorTest")
@MicronautTest
class ApplicationContentSecurityPolicyGeneratorTest {

    @Test
    void theCustomGeneratorDefinesTheResponseHeader(@Client("/") HttpClient httpClient) {
        HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/csp-generator"), String.class);

        assertEquals("default-src 'self'; object-src 'none'", response.header("Content-Security-Policy"));
    }

    @Requires(property = "spec.name", value = "ApplicationContentSecurityPolicyGeneratorTest")
    @Controller("/csp-generator")
    static class CspGeneratorController {

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get
        String index() {
            return "ok";
        }
    }
}
