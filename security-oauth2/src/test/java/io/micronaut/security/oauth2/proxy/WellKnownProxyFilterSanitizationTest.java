package io.micronaut.security.oauth2.proxy;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that {@link WellKnownProxyFilter} neither forwards the caller's credentials to the authorization server
 * nor relays untrusted response headers and non-JSON bodies from the authorization server to the application's origin.
 */
class WellKnownProxyFilterSanitizationTest {

    private static final String JSON_BODY = "{\"issuer\":\"https://auth.example.com/\"}";

    enum Mode { JSON, HTML, ERROR }

    private static final AtomicReference<Mode> MODE = new AtomicReference<>(Mode.JSON);
    private static final List<Map<String, List<String>>> RECEIVED_HEADERS = new ArrayList<>();

    @AfterEach
    void reset() {
        MODE.set(Mode.JSON);
        synchronized (RECEIVED_HEADERS) {
            RECEIVED_HEADERS.clear();
        }
    }

    @Test
    void credentialsAreNotForwardedAndUntrustedResponseHeadersAreDropped() {
        Map<String, Object> authServerConfiguration = Map.of(
            "spec.name", "WellKnownProxyFilterSanitizationTestAuthServer"
        );
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class, authServerConfiguration)) {
            try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, serverConfig(authServer))) {
                try (HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
                    BlockingHttpClient client = httpClient.toBlocking();
                    for (String path : List.of("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server")) {
                        HttpRequest<?> request = HttpRequest.GET(path + "?foo=bar")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer test-fixture-not-a-secret")
                            .header(HttpHeaders.PROXY_AUTHORIZATION, "Basic test-fixture-not-a-secret")
                            .header("X-Forwarded-For", "203.0.113.7")
                            .cookie(Cookie.of("JWT", "test-fixture-not-a-secret"));
                        HttpResponse<String> response = client.exchange(request, String.class);

                        Map<String, List<String>> upstreamHeaders = lastReceivedHeaders();
                        assertNotNull(upstreamHeaders);
                        assertFalse(upstreamHeaders.containsKey(HttpHeaders.COOKIE.toLowerCase()), "Cookie forwarded to issuer: " + upstreamHeaders);
                        assertFalse(upstreamHeaders.containsKey(HttpHeaders.AUTHORIZATION.toLowerCase()), "Authorization forwarded to issuer: " + upstreamHeaders);
                        assertFalse(upstreamHeaders.containsKey(HttpHeaders.PROXY_AUTHORIZATION.toLowerCase()), "Proxy-Authorization forwarded to issuer: " + upstreamHeaders);
                        assertFalse(upstreamHeaders.containsKey("x-forwarded-for"), "arbitrary caller headers forwarded to issuer: " + upstreamHeaders);
                        assertEquals(List.of(path), upstreamHeaders.get("x-request-path"), "query string must not be forwarded");

                        assertEquals(HttpStatus.OK, response.getStatus());
                        assertEquals(JSON_BODY, response.body());
                        assertTrue(response.getContentType().map(ct -> ct.matches(MediaType.APPLICATION_JSON_TYPE)).orElse(false),
                            "Content-Type should be JSON");
                        assertTrue(response.getHeaders().getAll(HttpHeaders.SET_COOKIE).isEmpty(),
                            "Set-Cookie from the authorization server must not reach the client");
                        assertFalse(response.getHeaders().contains("X-Upstream-Custom"),
                            "arbitrary upstream headers must not reach the client");
                        assertEquals("nosniff", response.getHeaders().get("X-Content-Type-Options"));
                    }
                }
            }
        }
    }

    @Test
    void nonJsonUpstreamResponseIsRejected() {
        MODE.set(Mode.HTML);
        assertBadGateway();
    }

    @Test
    void upstreamErrorResponseIsRejected() {
        MODE.set(Mode.ERROR);
        assertBadGateway();
    }

    private static void assertBadGateway() {
        Map<String, Object> authServerConfiguration = Map.of(
            "spec.name", "WellKnownProxyFilterSanitizationTestAuthServer"
        );
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class, authServerConfiguration)) {
            try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, serverConfig(authServer))) {
                try (HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
                    BlockingHttpClient client = httpClient.toBlocking();
                    HttpRequest<?> request = HttpRequest.GET("/.well-known/openid-configuration");
                    HttpClientResponseException e = assertThrows(HttpClientResponseException.class, () -> client.exchange(request, String.class));
                    assertEquals(HttpStatus.BAD_GATEWAY, e.getStatus());
                    assertTrue(e.getResponse().getBody(String.class).map(String::isEmpty).orElse(true),
                        "upstream body must not be relayed");
                    assertTrue(e.getResponse().getHeaders().getAll(HttpHeaders.SET_COOKIE).isEmpty());
                }
            }
        }
    }

    private static Map<String, Object> serverConfig(EmbeddedServer authServer) {
        return new HashMap<>(Map.of(
            "spec.name", "WellKnownProxyFilterSanitizationTest",
            "micronaut.security.oauth2.clients.authserver.client-id", "test-client-id",
            "micronaut.security.oauth2.clients.authserver.client-secret", "test-fixture-not-a-secret",
            "micronaut.security.oauth2.clients.authserver.proxy-well-known-oauth-authorization-server", StringUtils.TRUE,
            "micronaut.security.oauth2.clients.authserver.proxy-well-known-openid-configuration", StringUtils.TRUE,
            "micronaut.security.oauth2.clients.authserver.openid.issuer", authServer.getURL().toString()
        ));
    }

    private static Map<String, List<String>> lastReceivedHeaders() {
        synchronized (RECEIVED_HEADERS) {
            return RECEIVED_HEADERS.isEmpty() ? null : RECEIVED_HEADERS.get(RECEIVED_HEADERS.size() - 1);
        }
    }

    @Requires(property = "spec.name", value = "WellKnownProxyFilterSanitizationTestAuthServer")
    @Controller
    @Secured(SecurityRule.IS_ANONYMOUS)
    static class AuthServerController {

        @Get("/.well-known/oauth-authorization-server")
        HttpResponse<?> oauthAuthorizationServer(HttpRequest<?> request) {
            return respond(request);
        }

        @Get("/.well-known/openid-configuration")
        HttpResponse<?> openIdConfiguration(HttpRequest<?> request) {
            return respond(request);
        }

        private static HttpResponse<?> respond(HttpRequest<?> request) {
            Map<String, List<String>> headers = new HashMap<>();
            for (String name : request.getHeaders().names()) {
                headers.put(name.toLowerCase(), request.getHeaders().getAll(name));
            }
            headers.put("x-request-path", List.of(request.getUri().toString()));
            synchronized (RECEIVED_HEADERS) {
                RECEIVED_HEADERS.add(headers);
            }
            MutableHttpResponse<?> response = switch (MODE.get()) {
                case JSON -> HttpResponse.ok(JSON_BODY).contentType(MediaType.APPLICATION_JSON_TYPE);
                case HTML -> HttpResponse.ok("<html><body><script>alert(1)</script></body></html>").contentType(MediaType.TEXT_HTML_TYPE);
                case ERROR -> HttpResponse.serverError("<html>upstream error</html>").contentType(MediaType.TEXT_HTML_TYPE);
            };
            return response
                .cookie(Cookie.of("JWT", "test-fixture-not-a-secret").path("/"))
                .header("X-Upstream-Custom", "untrusted");
        }
    }
}
