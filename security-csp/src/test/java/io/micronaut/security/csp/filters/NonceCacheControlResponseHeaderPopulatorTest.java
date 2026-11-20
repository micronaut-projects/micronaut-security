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
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.csp.ContentSecurityPolicy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NonceCacheControlResponseHeaderPopulatorTest {
    private static final String SPEC_NAME = "NonceCacheControlResponseHeaderPopulatorTest";
    private static final String NONCE = "micronaut.security.csp.script-src.nonce";
    private static final String NONCE_CACHE_CONTROL = "micronaut.security.csp.filter.nonce-cache-control";

    @ParameterizedTest
    @ValueSource(strings = {"/nonce-cache/html", "/nonce-cache/xhtml"})
    void documentsThatCarryANonceReceivePrivateCacheControlByDefault(String path) {
        try (EmbeddedServer server = server(Map.of(NONCE, true))) {
            HttpResponse<String> response = get(server, path);

            assertTrue(response.header(ContentSecurityPolicy.CONTENT_SECURITY_POLICY).contains("'nonce-"));
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

            assertNotNull(response.header(ContentSecurityPolicy.CONTENT_SECURITY_POLICY));
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
    void blankCacheControlIsNotWritten(String value) {
        try (EmbeddedServer server = server(Map.of(NONCE, true, NONCE_CACHE_CONTROL, value))) {
            assertNull(get(server, "/nonce-cache/html").header(HttpHeaders.CACHE_CONTROL));
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

        @Get("/own")
        @Produces(MediaType.TEXT_HTML)
        HttpResponse<String> own() {
            return HttpResponse.ok("<!DOCTYPE html><html><head><title>Page</title></head><body></body></html>")
                .header(HttpHeaders.CACHE_CONTROL, "no-store");
        }
    }
}
