package io.micronaut.security.docs.cspnonce;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.views.ModelAndView;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = "spec.name", value = "CspNonceViewModelProcessorTest")
@Property(name = "micronaut.security.csp.script-src.nonce", value = "true")
@MicronautTest
class CspNonceViewModelProcessorTest {
    private static final Pattern SCRIPT_NONCE = Pattern.compile("<script nonce=\"([^\"]+)\">");

    @Test
    void theViewRendersTheNonceOfTheResponseHeader(@Client("/") HttpClient httpClient) {
        HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/csp-nonce"), String.class);

        Matcher matcher = SCRIPT_NONCE.matcher(response.body());
        assertTrue(matcher.find(), "the view must render the nonce");
        String contentSecurityPolicy = response.header("Content-Security-Policy");
        assertNotNull(contentSecurityPolicy);
        assertTrue(contentSecurityPolicy.contains("'nonce-" + matcher.group(1) + "'"));
    }

    @Requires(property = "spec.name", value = "CspNonceViewModelProcessorTest")
    @Controller("/csp-nonce")
    static class CspNonceController {

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.TEXT_HTML)
        @Get
        ModelAndView<Map<String, Object>> index() {
            return new ModelAndView<>("csp-nonce", Map.of("title", "CSP nonce"));
        }
    }
}
