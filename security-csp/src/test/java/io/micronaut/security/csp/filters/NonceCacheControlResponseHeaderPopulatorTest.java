/*
 * Copyright 2017-2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.csp.filters;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.http.HttpHeaderEntry;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Error;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.annotation.Status;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NonceCacheControlResponseHeaderPopulatorTest {
    private static final String SPEC_NAME = "NonceCacheControlResponseHeaderPopulatorTest";
    private static final String NONCE = "micronaut.security.csp.script-src.nonce";
    private static final String NONCE_CACHE_CONTROL = "micronaut.security.csp.filter.nonce-cache-control";
    private static final String HTML_NOT_FOUND_PAGE = "nonce-cache.html-not-found-page";
    private static final List<HttpHeaderEntry> PRIVATE = List.of(new HttpHeaderEntry(HttpHeaders.CACHE_CONTROL, "private"));

    @ParameterizedTest
    @ValueSource(strings = {"/nonce-cache/html", "/nonce-cache/xhtml"})
    void documentsThatCarryANonceReceivePrivateCacheControlByDefault(String path) {
        try (EmbeddedServer server = server(Map.of(NONCE, true))) {
            HttpResponse<String> response = get(server, path);

            assertTrue(response.header(HttpHeaders.CONTENT_SECURITY_POLICY).contains("'nonce-"));
            assertEquals("private", response.header(HttpHeaders.CACHE_CONTROL));
        }
    }

    @Test
    void configuredCacheControlReplacesTheDefault() {
        try (EmbeddedServer server = server(Map.of(NONCE, true, NONCE_CACHE_CONTROL, "no-store"))) {
            assertEquals("no-store", get(server, "/nonce-cache/html").header(HttpHeaders.CACHE_CONTROL));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"/nonce-cache/json", "/nonce-cache/text"})
    void responsesThatCannotCarryANonceKeepTheirCaching(String path) {
        try (EmbeddedServer server = server(Map.of(NONCE, true, NONCE_CACHE_CONTROL, "private"))) {
            HttpResponse<String> response = get(server, path);

            assertNotNull(response.header(HttpHeaders.CONTENT_SECURITY_POLICY));
            assertNull(response.header(HttpHeaders.CACHE_CONTROL));
        }
    }

    @Test
    void negotiatedContentTypeDecidesWhetherCacheControlIsWritten() {
        try (EmbeddedServer server = server(Map.of(NONCE, true, NONCE_CACHE_CONTROL, "private"));
             HttpClient httpClient = HttpClient.create(server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();

            HttpResponse<String> html = client.exchange(HttpRequest.GET("/nonce-cache/negotiated").accept(MediaType.TEXT_HTML), String.class);
            HttpResponse<String> text = client.exchange(HttpRequest.GET("/nonce-cache/negotiated").accept(MediaType.TEXT_PLAIN), String.class);

            assertEquals("private", html.header(HttpHeaders.CACHE_CONTROL));
            assertNull(text.header(HttpHeaders.CACHE_CONTROL));
        }
    }

    @Test
    void populatorRejectsABlankCacheControl() {
        ConfigurationException exception = assertThrows(ConfigurationException.class, () -> populator(" ", (request, response) -> null));

        assertTrue(exception.getMessage().startsWith(NONCE_CACHE_CONTROL));
    }

    @Test
    void populatorWritesNothingForARequestWithoutANonce() {
        assertNull(populator("private", (request, response) -> MediaType.TEXT_HTML_TYPE)
            .findHttpHeaders(HttpRequest.GET("/"), HttpResponse.ok().contentType(MediaType.TEXT_HTML_TYPE)));
    }

    @Test
    void populatorUsesTheContentTypeOfTheResponseBeforeTheOneOfTheRoute() {
        NonceCacheControlResponseHeaderPopulator populator = populator("private", (request, response) -> MediaType.TEXT_HTML_TYPE);

        assertNull(populator.findHttpHeaders(requestWithNonce(), HttpResponse.ok().contentType(MediaType.APPLICATION_JSON_TYPE)));
        assertEquals(PRIVATE, populator.findHttpHeaders(requestWithNonce(), HttpResponse.ok()));
    }

    @Test
    void populatorIgnoresContentTypeParameters() {
        assertEquals(PRIVATE, populator("private", (request, response) -> null)
            .findHttpHeaders(requestWithNonce(), HttpResponse.ok().contentType("text/html; charset=utf-8")));
    }

    @Test
    void populatorWritesNothingWhenTheContentTypeCannotBeTold() {
        assertNull(populator("private", (request, response) -> null).findHttpHeaders(requestWithNonce(), HttpResponse.ok()));
    }

    @Test
    void jsonErrorResponsesReceiveNoCacheControl() {
        try (EmbeddedServer server = server(Map.of(NONCE, true))) {
            HttpResponse<?> notFound = error(server, "/nonce-cache/no-such-path");
            HttpResponse<?> failure = error(server, "/nonce-cache/failure");

            assertEquals(HttpStatus.NOT_FOUND, notFound.getStatus());
            assertNull(notFound.header(HttpHeaders.CACHE_CONTROL));
            assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, failure.getStatus());
            assertNull(failure.header(HttpHeaders.CACHE_CONTROL));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"/nonce-cache/html-error", "/nonce-cache/html-error-produces"})
    void htmlErrorPagesThatCarryANonceReceiveCacheControl(String path) {
        try (EmbeddedServer server = server(Map.of(NONCE, true))) {
            HttpResponse<?> response = error(server, path);

            assertEquals(HttpStatus.CONFLICT, response.getStatus());
            assertTrue(response.header(HttpHeaders.CONTENT_SECURITY_POLICY).contains("'nonce-"));
            assertEquals("private", response.header(HttpHeaders.CACHE_CONTROL));
        }
    }

    @Test
    void htmlPageOfAStatusErrorHandlerReceivesCacheControl() {
        try (EmbeddedServer server = server(Map.of(NONCE, true, HTML_NOT_FOUND_PAGE, true))) {
            HttpResponse<?> response = error(server, "/nonce-cache/no-such-path");

            assertEquals(HttpStatus.NOT_FOUND, response.getStatus());
            assertTrue(response.header(HttpHeaders.CONTENT_SECURITY_POLICY).contains("'nonce-"));
            assertEquals("private", response.header(HttpHeaders.CACHE_CONTROL));
        }
    }

    @Test
    void populatorIsLoadedWhenADirectiveUsesNoncesAndCacheControlIsConfigured() {
        try (EmbeddedServer server = server(Map.of(NONCE, true))) {
            assertTrue(server.getApplicationContext().containsBean(NonceCacheControlResponseHeaderPopulator.class));
        }
    }

    @Test
    void cacheControlSetByTheApplicationIsKept() {
        try (EmbeddedServer server = server(Map.of(NONCE, true))) {
            HttpResponse<String> response = get(server, "/nonce-cache/own");

            assertEquals(1, response.getHeaders().getAll(HttpHeaders.CACHE_CONTROL).size());
            assertEquals("no-store", response.header(HttpHeaders.CACHE_CONTROL));
        }
    }

    @Test
    void htmlOutsideTheFilterPatternReceivesNoCacheControl() {
        try (EmbeddedServer server = server(Map.of(NONCE, true, NONCE_CACHE_CONTROL, "private",
            "micronaut.security.csp.filter.pattern", "/other/**"))) {
            assertNull(get(server, "/nonce-cache/html").header(HttpHeaders.CACHE_CONTROL));
        }
    }

    @Test
    void cacheControlIsNotWrittenWhenNoDirectiveUsesNonces() {
        try (EmbeddedServer server = server(Map.of())) {
            assertFalse(server.getApplicationContext().containsBean(NonceCacheControlResponseHeaderPopulator.class));
            assertNull(get(server, "/nonce-cache/html").header(HttpHeaders.CACHE_CONTROL));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " "})
    void populatorIsNotLoadedForABlankCacheControl(String value) {
        try (EmbeddedServer server = server(Map.of(NONCE, true, NONCE_CACHE_CONTROL, value))) {
            assertFalse(server.getApplicationContext().containsBean(NonceCacheControlResponseHeaderPopulator.class));
            assertNull(get(server, "/nonce-cache/html").header(HttpHeaders.CACHE_CONTROL));
        }
    }

    private static NonceCacheControlResponseHeaderPopulator populator(String cacheControl,
                                                                      BiFunction<HttpRequest<?>, HttpResponse<?>, @Nullable MediaType> routeContentType) {
        ContentSecurityPolicyFilterConfigurationProperties configuration = new ContentSecurityPolicyFilterConfigurationProperties();
        configuration.setNonceCacheControl(cacheControl);
        return new NonceCacheControlResponseHeaderPopulator(configuration, routeContentType);
    }

    private static HttpRequest<?> requestWithNonce() {
        MutableHttpRequest<?> request = HttpRequest.GET("/");
        request.setAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, "nonce");
        return request;
    }

    private static HttpResponse<?> error(EmbeddedServer server, String path) {
        try (HttpClient httpClient = HttpClient.create(server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
                () -> client.exchange(HttpRequest.GET(path), String.class));
            return exception.getResponse();
        }
    }

    private static EmbeddedServer server(Map<String, Object> configuration) {
        Map<String, Object> properties = new HashMap<>(configuration);
        properties.put("spec.name", SPEC_NAME);
        return ApplicationContext.run(EmbeddedServer.class, properties);
    }

    private static HttpResponse<String> get(EmbeddedServer server, String path) {
        try (HttpClient httpClient = HttpClient.create(server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            return client.exchange(HttpRequest.GET(path), String.class);
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller("/nonce-cache")
    static final class TestController {
        @Get("/html")
        @Produces(MediaType.TEXT_HTML)
        String html() {
            return "<!DOCTYPE html><html><head><title>Page</title></head><body></body></html>";
        }

        @Get("/xhtml")
        @Produces(MediaType.APPLICATION_XHTML)
        String xhtml() {
            return "<html xmlns=\"http://www.w3.org/1999/xhtml\"><head><title>Page</title></head><body></body></html>";
        }

        @Get("/json")
        Map<String, String> json() {
            return Map.of("message", "Hello");
        }

        @Get("/text")
        @Produces(MediaType.TEXT_PLAIN)
        String text() {
            return "Hello";
        }

        @Get("/negotiated")
        @Produces({MediaType.TEXT_PLAIN, MediaType.TEXT_HTML})
        String negotiated() {
            return "Hello";
        }

        @Get("/failure")
        String failure() {
            throw new IllegalStateException("failure");
        }

        @Get("/html-error")
        String htmlError() {
            throw new UnsupportedOperationException("html error");
        }

        @Get("/html-error-produces")
        String htmlErrorProduces() {
            throw new IllegalArgumentException("html error");
        }

        @Error(UnsupportedOperationException.class)
        HttpResponse<String> onHtmlError() {
            return HttpResponse.<String>status(HttpStatus.CONFLICT)
                .body("<!DOCTYPE html><html><head><title>Error</title></head><body></body></html>")
                .contentType(MediaType.TEXT_HTML_TYPE);
        }

        @Error(IllegalArgumentException.class)
        @Produces(MediaType.TEXT_HTML)
        @Status(HttpStatus.CONFLICT)
        String onHtmlErrorProduces() {
            return "<!DOCTYPE html><html><head><title>Error</title></head><body></body></html>";
        }

        @Get("/own")
        @Produces(MediaType.TEXT_HTML)
        HttpResponse<String> own() {
            return HttpResponse.ok("<!DOCTYPE html><html><head><title>Page</title></head><body></body></html>")
                .header(HttpHeaders.CACHE_CONTROL, "no-store");
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Requires(property = HTML_NOT_FOUND_PAGE, value = "true")
    @Controller("/nonce-cache-not-found")
    static final class NotFoundPageController {
        @Error(status = HttpStatus.NOT_FOUND, global = true)
        @Produces(MediaType.TEXT_HTML)
        String notFound() {
            return "<!DOCTYPE html><html><head><title>Not found</title></head><body></body></html>";
        }
    }
}
