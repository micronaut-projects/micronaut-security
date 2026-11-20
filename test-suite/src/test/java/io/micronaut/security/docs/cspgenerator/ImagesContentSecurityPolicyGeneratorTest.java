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
import io.micronaut.security.csp.ContentSecurityPolicy;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Property(name = "spec.name", value = "ImagesContentSecurityPolicyGeneratorTest")
@Property(name = "micronaut.security.csp.script-src.self", value = "true")
@MicronautTest
class ImagesContentSecurityPolicyGeneratorTest {

    @Test
    void theOverriddenDirectiveReplacesTheConfiguredOne(@Client("/") HttpClient httpClient) {
        HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/csp-generator-images"), String.class);

        ContentSecurityPolicy policy = ContentSecurityPolicy.of(response);
        assertNotNull(policy);
        assertEquals("img-src 'self' https://images.example.com", policy.imgSrc().toHeaderValue());
        assertEquals("script-src 'self'", policy.scriptSrc().toHeaderValue(), "the configuration keeps applying to other directives");
    }

    @Requires(property = "spec.name", value = "ImagesContentSecurityPolicyGeneratorTest")
    @Controller("/csp-generator-images")
    static class ImagesController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get
        String index() {
            return "ok";
        }
    }
}
