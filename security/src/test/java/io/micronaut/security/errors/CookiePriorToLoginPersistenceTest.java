/*
 * Copyright 2026 original authors
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
package io.micronaut.security.errors;

import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.simple.SimpleHttpRequest;
import io.netty.handler.codec.http.cookie.ClientCookieDecoder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The URI persisted prior to login must only ever point to a local path (CWE-601).
 */
class CookiePriorToLoginPersistenceTest {
    private static final String COOKIE_NAME = "ORIGINAL_URI";

    private final CookiePriorToLoginPersistence persistence = new CookiePriorToLoginPersistence(null);

    @ParameterizedTest
    @CsvSource({
        "/secured, /secured",
        "/secured?foo=bar&baz=1, /secured?foo=bar&baz=1",
        "/a/b%2Fc?q=%2F%2Fevil.example, /a/b%2Fc?q=%2F%2Fevil.example",
        "///evil.example/x, /evil.example/x",
        "//evil.example/x, /x",
        "http://app.example/secured?foo=bar, /secured?foo=bar"
    })
    void onUnauthorizedPersistsOnlyTheLocalPathAndQuery(String requestUri, String expectedCookieValue) {
        MutableHttpResponse<?> response = HttpResponse.ok();
        persistence.onUnauthorized(new SimpleHttpRequest<>(HttpMethod.GET, requestUri, null), response);
        Optional<io.netty.handler.codec.http.cookie.Cookie> cookie = cookie(response, COOKIE_NAME);
        assertTrue(cookie.isPresent());
        assertEquals(expectedCookieValue, cookie.get().value());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "////evil.example/x",
        "http://evil.example",
        "mailto:someone@evil.example"
    })
    void onUnauthorizedDoesNotPersistNonLocalPaths(String requestUri) {
        MutableHttpResponse<?> response = HttpResponse.ok();
        persistence.onUnauthorized(new SimpleHttpRequest<>(HttpMethod.GET, requestUri, null), response);
        assertFalse(cookie(response, COOKIE_NAME).isPresent(), () -> requestUri + " must not be persisted");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "/secured",
        "/secured?foo=bar",
        "/",
        // percent-encoded slashes stay encoded in the Location header and are therefore a local path
        "/%2F/evil.example"
    })
    void getOriginalUriReturnsLocalPaths(String cookieValue) {
        MutableHttpResponse<?> response = HttpResponse.ok();
        Optional<URI> originalUri = persistence.getOriginalUri(loginRequest(cookieValue), response);
        assertTrue(originalUri.isPresent());
        assertEquals(cookieValue, originalUri.get().toString());
        assertCookieCleared(response);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "//evil.example/x",
        "///evil.example/x",
        "////evil.example/x",
        "https://evil.example/x",
        "evil.example/x",
        "javascript:alert(1)",
        "/\\evil.example",
        "/has space"
    })
    void getOriginalUriIgnoresNonLocalValues(String cookieValue) {
        MutableHttpResponse<?> response = HttpResponse.ok();
        Optional<URI> originalUri = persistence.getOriginalUri(loginRequest(cookieValue), response);
        assertFalse(originalUri.isPresent(), () -> cookieValue + " must be ignored");
        assertCookieCleared(response);
    }

    private static MutableHttpRequest<?> loginRequest(String cookieValue) {
        return new SimpleHttpRequest<>(HttpMethod.POST, "/login", null).cookie(Cookie.of(COOKIE_NAME, cookieValue));
    }

    private static void assertCookieCleared(MutableHttpResponse<?> response) {
        Optional<io.netty.handler.codec.http.cookie.Cookie> cleared = cookie(response, COOKIE_NAME);
        assertTrue(cleared.isPresent(), "cookie should be expired once read");
        assertEquals("", cleared.get().value());
        assertEquals(0, cleared.get().maxAge());
    }

    /**
     * On this branch the Netty response does not expose the cookies it was given, so they are read back from the Set-Cookie headers.
     */
    private static Optional<io.netty.handler.codec.http.cookie.Cookie> cookie(MutableHttpResponse<?> response, String name) {
        return response.getHeaders().getAll(HttpHeaders.SET_COOKIE).stream()
            .map(ClientCookieDecoder.LAX::decode)
            .filter(c -> c != null && name.equals(c.name()))
            .findFirst();
    }
}
