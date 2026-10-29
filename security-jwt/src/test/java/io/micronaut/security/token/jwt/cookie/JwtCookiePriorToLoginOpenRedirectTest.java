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
package io.micronaut.security.token.jwt.cookie;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider;
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * With {@code micronaut.security.redirect.prior-to-login=true} the application remembers the URI of the request
 * that was rejected with 401 and redirects back to it after login. A request line such as
 * {@code GET ///evil.example/x} or {@code GET //evil.example/x} must not turn that redirect into a redirect to
 * another host (browsers interpret a {@code Location} starting with {@code //} as scheme-relative).
 */
class JwtCookiePriorToLoginOpenRedirectTest {
    private static final String SPEC_NAME = "JwtCookiePriorToLoginOpenRedirectTest";
    private static final String ORIGINAL_URI_COOKIE = "ORIGINAL_URI";

    private static EmbeddedServer server;
    private static HttpClient httpClient;

    @BeforeAll
    static void start() {
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("spec.name", SPEC_NAME);
        configuration.put("micronaut.http.client.follow-redirects", StringUtils.FALSE);
        configuration.put("micronaut.security.authentication", "cookie");
        configuration.put("micronaut.security.redirect.prior-to-login", StringUtils.TRUE);
        configuration.put("micronaut.security.redirect.unauthorized.url", "/login/auth");
        configuration.put("micronaut.security.token.jwt.signatures.secret.generator.secret", "test-fixture-not-a-secret-0123456789");
        server = ApplicationContext.run(EmbeddedServer.class, configuration);
        httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
    }

    @AfterAll
    static void stop() {
        httpClient.close();
        server.close();
    }

    @Test
    void redirectsBackToTheLocalPathRequestedPriorToLogin() throws IOException {
        RawResponse unauthorized = rawGet("/secured?foo=bar");
        assertEquals(303, unauthorized.status);
        Optional<String> originalUri = unauthorized.cookieValue(ORIGINAL_URI_COOKIE);
        assertTrue(originalUri.isPresent(), "ORIGINAL_URI cookie should be set for a local path");

        HttpResponse<?> loginResponse = login(originalUri.get());
        assertEquals(HttpStatus.SEE_OTHER, loginResponse.status());
        assertEquals("/secured?foo=bar", loginResponse.getHeaders().get("Location"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "///evil.example/x",
        "//evil.example/x",
        "////evil.example/x",
        "http://evil.example/x"
    })
    void loginNeverRedirectsToAnotherHostBecauseOfTheRequestLine(String requestTarget) throws IOException {
        RawResponse unauthorized = rawGet(requestTarget);
        Optional<String> originalUri = unauthorized.cookieValue(ORIGINAL_URI_COOKIE);
        if (!originalUri.isPresent()) {
            return; // nothing persisted, nothing to redirect to
        }
        HttpResponse<?> loginResponse = login(originalUri.get());
        assertEquals(HttpStatus.SEE_OTHER, loginResponse.status());
        String location = loginResponse.getHeaders().get("Location");
        assertTrue(location.startsWith("/"), () -> "Location must be a local path: " + location);
        assertFalse(location.startsWith("//"), () -> "Location must not be scheme-relative: " + location);
        URI locationUri = URI.create(location);
        assertNull(locationUri.getScheme(), () -> "Location must not carry a scheme: " + location);
        assertNull(locationUri.getRawAuthority(), () -> "Location must not carry an authority: " + location);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "//evil.example/x",
        "///evil.example/x",
        "https://evil.example/x",
        "evil.example/x"
    })
    void plantedOriginalUriCookieIsIgnored(String plantedValue) {
        HttpResponse<?> loginResponse = login(plantedValue);
        assertEquals(HttpStatus.SEE_OTHER, loginResponse.status());
        assertEquals("/", loginResponse.getHeaders().get("Location"));
    }

    private static HttpResponse<?> login(String originalUriCookieValue) {
        Map<String, String> credentials = new HashMap<>();
        credentials.put("username", "sherlock");
        credentials.put("password", "password");
        HttpRequest<?> loginRequest = HttpRequest.POST("/login", credentials)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
            .cookie(Cookie.of(ORIGINAL_URI_COOKIE, originalUriCookieValue));
        return httpClient.toBlocking().exchange(loginRequest, String.class);
    }

    private static RawResponse rawGet(String requestTarget) throws IOException {
        try (Socket socket = new Socket(server.getHost(), server.getPort())) {
            OutputStream out = socket.getOutputStream();
            String request = "GET " + requestTarget + " HTTP/1.1\r\n"
                + "Host: " + server.getHost() + ":" + server.getPort() + "\r\n"
                + "Accept: text/html\r\n"
                + "Connection: close\r\n\r\n";
            out.write(request.getBytes(StandardCharsets.US_ASCII));
            out.flush();
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.ISO_8859_1));
            String statusLine = reader.readLine();
            int status = Integer.parseInt(statusLine.split(" ")[1]);
            List<String> headers = new ArrayList<>();
            String line;
            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                headers.add(line);
            }
            return new RawResponse(status, headers);
        }
    }

    private static final class RawResponse {
        private final int status;
        private final List<String> headers;

        private RawResponse(int status, List<String> headers) {
            this.status = status;
            this.headers = headers;
        }

        Optional<String> cookieValue(String name) {
            return headers.stream()
                .filter(h -> h.regionMatches(true, 0, "Set-Cookie:", 0, "Set-Cookie:".length()))
                .map(h -> h.substring("Set-Cookie:".length()).trim())
                .filter(c -> c.startsWith(name + "="))
                .map(c -> c.substring(name.length() + 1, c.indexOf(';') > 0 ? c.indexOf(';') : c.length()))
                .findFirst();
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class AuthProvider extends MockAuthenticationProvider {
        AuthProvider() {
            super(Collections.singletonList(new SuccessAuthenticationScenario("sherlock")));
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller("/secured")
    static class SecuredController {
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String index() {
            return "secured";
        }
    }
}
