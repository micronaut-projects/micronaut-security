package io.micronaut.security.cspsecurity;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.csp.ContentSecurityPolicy;
import io.micronaut.security.rules.SecurityRule;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Responses that the security and Fetch Metadata filters return early still carry the policy,
 * because the CSP filter runs before them.
 */
class CspOnSecurityRejectionsTest {
    private static final String SPEC_NAME = "CspOnSecurityRejectionsTest";
    private static final String DEFAULT_POLICY = "base-uri 'none'; default-src 'none'; connect-src 'none'; font-src 'none'; "
        + "object-src 'none'; require-trusted-types-for 'script'; frame-ancestors 'none'; frame-src 'none'; img-src 'none'; "
        + "manifest-src 'none'; media-src 'none'; form-action 'self'; worker-src 'none'; style-src 'none'; script-src 'none'";

    @Test
    void anUnauthorizedResponseCarriesTheDefaultPolicy() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", SPEC_NAME));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
                () -> httpClient.toBlocking().exchange(HttpRequest.GET("/csp-secured").accept(MediaType.TEXT_HTML)));

            assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatus());
            assertEquals(DEFAULT_POLICY, exception.getResponse().header(HttpHeaders.CONTENT_SECURITY_POLICY));
        }
    }

    @Test
    void anUnauthorizedResponseCarriesTheNonceOfItsRequest() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", SPEC_NAME,
                "micronaut.security.csp.script-src.nonce", true));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
                () -> httpClient.toBlocking().exchange(HttpRequest.GET("/csp-secured").accept(MediaType.TEXT_HTML)));

            ContentSecurityPolicy policy = ContentSecurityPolicy.of(exception.getResponse());
            assertNotNull(policy);
            assertTrue(policy.scriptSrc().value().startsWith("'nonce-"), policy::toString);
            assertEquals("private", exception.getResponse().header(HttpHeaders.CACHE_CONTROL),
                "the HTML page of the rejected request may carry the nonce, so shared caches must not store it");
        }
    }

    @Test
    void aJsonUnauthorizedResponseKeepsItsCaching() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", SPEC_NAME,
                "micronaut.security.csp.script-src.nonce", true));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
                () -> httpClient.toBlocking().exchange(HttpRequest.GET("/csp-secured/json")));

            assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatus());
            assertNotNull(ContentSecurityPolicy.of(exception.getResponse()));
            assertNull(exception.getResponse().header(HttpHeaders.CACHE_CONTROL));
        }
    }

    @Test
    void anUnauthorizedResponseCarriesThePolicyWhenThePatternIsNarrowed() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", SPEC_NAME,
                "micronaut.security.csp.filter.pattern", "/csp-secured/**"));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
                () -> httpClient.toBlocking().exchange(HttpRequest.GET("/csp-secured/json")));

            assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatus());
            assertEquals(DEFAULT_POLICY, exception.getResponse().header(HttpHeaders.CONTENT_SECURITY_POLICY),
                "the CSP filter marked the request before the security filter rejected it");
        }
    }

    @Test
    void aCrossSiteRequestRejectedByFetchMetadataCarriesThePolicy() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", SPEC_NAME));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
                () -> httpClient.toBlocking().exchange(HttpRequest.GET("/csp-secured")
                    .header(HttpHeaders.SEC_FETCH_SITE, "cross-site")
                    .header(HttpHeaders.SEC_FETCH_MODE, "no-cors")
                    .header(HttpHeaders.SEC_FETCH_DEST, "image")));

            assertEquals(HttpStatus.FORBIDDEN, exception.getStatus());
            assertEquals(DEFAULT_POLICY, exception.getResponse().header(HttpHeaders.CONTENT_SECURITY_POLICY));
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller("/csp-secured")
    static class SecuredController {
        @Get(produces = MediaType.TEXT_HTML)
        String page() {
            return "<html><body>secured</body></html>";
        }

        @Get(uri = "/json", produces = MediaType.APPLICATION_JSON)
        Map<String, String> json() {
            return Map.of("secured", "true");
        }
    }
}
