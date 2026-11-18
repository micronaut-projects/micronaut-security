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
package io.micronaut.security.session;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.provider.HttpRequestExecutorAuthenticationProvider;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * With {@code micronaut.security.redirect.prior-to-login=true}, {@link SessionLoginHandler} redirects back to the
 * URI persisted in the {@code ORIGINAL_URI} cookie. A planted cookie must not turn that redirect into a redirect
 * to another host (CWE-601).
 */
class SessionPriorLoginRedirectTest {
    private static final String SPEC_NAME = "SessionPriorLoginRedirectTest";
    private static final String ORIGINAL_URI_COOKIE = "ORIGINAL_URI";
    private static final String LOGIN_SUCCESS = "/home";
    private static final String SECURED_PAGE = "/secured/page?foo=bar&baz=qux";

    private static EmbeddedServer server;
    private static HttpClient httpClient;
    private static BlockingHttpClient client;

    @BeforeAll
    static void start() {
        server = ApplicationContext.run(EmbeddedServer.class, Map.of(
            "spec.name", SPEC_NAME,
            "micronaut.http.client.follow-redirects", StringUtils.FALSE,
            "micronaut.security.authentication", "session",
            "micronaut.security.redirect.prior-to-login", StringUtils.TRUE,
            "micronaut.security.redirect.login-success", LOGIN_SUCCESS,
            "micronaut.security.redirect.unauthorized.url", "/login/auth"));
        httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
        client = httpClient.toBlocking();
    }

    @AfterAll
    static void stop() {
        httpClient.close();
        server.close();
    }

    @Test
    void redirectsBackToThePathAndQueryRequestedPriorToLogin() {
        HttpResponse<?> unauthorized = client.exchange(HttpRequest.GET(SECURED_PAGE).accept(MediaType.TEXT_HTML));
        assertEquals(HttpStatus.SEE_OTHER, unauthorized.status());
        assertEquals("/login/auth", unauthorized.header(HttpHeaders.LOCATION));
        Optional<Cookie> originalUri = unauthorized.getCookie(ORIGINAL_URI_COOKIE);
        assertTrue(originalUri.isPresent(), "the rejected request should be persisted");
        assertEquals(SECURED_PAGE, originalUri.get().getValue());

        HttpResponse<?> login = login(originalUri.get().getValue());
        assertEquals(HttpStatus.SEE_OTHER, login.status());
        assertEquals(SECURED_PAGE, login.header(HttpHeaders.LOCATION));
        assertOriginalUriCookieCleared(login);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "https://evil.example/x",
        "//evil.example/x"
    })
    void plantedOriginalUriCookieIsIgnoredAndCleared(String plantedValue) {
        HttpResponse<?> login = login(plantedValue);
        assertEquals(HttpStatus.SEE_OTHER, login.status());
        assertEquals(LOGIN_SUCCESS, login.header(HttpHeaders.LOCATION));
        assertOriginalUriCookieCleared(login);
    }

    @Test
    void redirectsToLoginSuccessWithoutAnOriginalUriCookie() {
        HttpResponse<?> login = login(null);
        assertEquals(HttpStatus.SEE_OTHER, login.status());
        assertEquals(LOGIN_SUCCESS, login.header(HttpHeaders.LOCATION));
        assertFalse(login.getCookie(ORIGINAL_URI_COOKIE).isPresent(), "there is no cookie to expire");
    }

    private static HttpResponse<?> login(String originalUriCookieValue) {
        MutableHttpRequest<?> request = HttpRequest.POST("/login", Map.of("username", "sherlock", "password", "password"));
        if (originalUriCookieValue != null) {
            request.cookie(Cookie.of(ORIGINAL_URI_COOKIE, originalUriCookieValue));
        }
        return client.exchange(request);
    }

    private static void assertOriginalUriCookieCleared(HttpResponse<?> response) {
        Optional<Cookie> cleared = response.getCookie(ORIGINAL_URI_COOKIE);
        assertTrue(cleared.isPresent(), "cookie should be expired once read");
        assertEquals(0, cleared.get().getMaxAge());
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class AuthProvider<B> implements HttpRequestExecutorAuthenticationProvider<B> {
        @Override
        public AuthenticationResponse authenticate(HttpRequest<B> requestContext, AuthenticationRequest<String, String> authRequest) {
            return AuthenticationResponse.success("sherlock");
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller("/secured")
    static class SecuredController {
        @Produces(MediaType.TEXT_HTML)
        @Get("/page")
        String page() {
            return "<html><body>secured</body></html>";
        }
    }
}
