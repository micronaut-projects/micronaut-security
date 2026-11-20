package io.micronaut.security.test.tomcat;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The CSP header and the nonce Cache-Control header are written by response header populators that
 * the HTTP server runs; this test proves they also run on the servlet runtime.
 */
@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "pleaseChangeThisSecretForANewOne")
@Property(name = "micronaut.security.csp.script-src.nonce", value = StringUtils.TRUE)
@Property(name = "spec.name", value = "ContentSecurityPolicyTest")
@MicronautTest
class ContentSecurityPolicyTest {

    @Inject
    @Client("/")
    HttpClient httpClient;

    @Test
    void tomcatResponsesCarryThePolicyWithTheRequestNonce() {
        HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/csp-tomcat"), String.class);

        String policy = response.header(HttpHeaders.CONTENT_SECURITY_POLICY);
        assertNotNull(policy);
        assertTrue(policy.contains("default-src 'none'"), policy);
        assertTrue(policy.contains("script-src 'nonce-" + nonce(response.body()) + "'"), policy);
        assertEquals("private", response.header(HttpHeaders.CACHE_CONTROL));
    }

    private static String nonce(String body) {
        return body.substring(body.indexOf("nonce=\"") + "nonce=\"".length(), body.indexOf("\">"));
    }

    @Requires(property = "spec.name", value = "ContentSecurityPolicyTest")
    @Controller("/csp-tomcat")
    static class CspController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.TEXT_HTML)
        @Get
        String index(HttpRequest<?> request) {
            String nonce = request.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, String.class).orElse("");
            return "<html><body><script nonce=\"" + nonce + "\"></script></body></html>";
        }
    }
}
