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

@Property(name = "spec.name", value = "UpgradingContentSecurityPolicyGeneratorTest")
@Property(name = "micronaut.security.csp.script-src.self", value = "true")
@MicronautTest
class UpgradingContentSecurityPolicyGeneratorTest {

    @Test
    void theSubclassAppendsADirectiveThatTheConfigurationDoesNotExpose(@Client("/") HttpClient httpClient) {
        HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/csp-generator-upgrade"), String.class);

        ContentSecurityPolicy policy = ContentSecurityPolicy.of(response);
        assertNotNull(policy);
        assertNotNull(policy.upgradeInsecureRequests());
        assertEquals("script-src 'self'", policy.scriptSrc().toHeaderValue(), "the configuration keeps applying to the other directives");
    }

    @Requires(property = "spec.name", value = "UpgradingContentSecurityPolicyGeneratorTest")
    @Controller("/csp-generator-upgrade")
    static class UpgradeController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get
        String index() {
            return "ok";
        }
    }
}
