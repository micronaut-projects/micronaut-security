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
package io.micronaut.security.rules;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.MockAuthenticationProvider;
import io.micronaut.security.SuccessAuthenticationScenario;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Fixed-depth intercept URL map patterns must be evaluated against the path the router sees,
 * so an encoded slash or a blank path variable cannot skip a role-restricted entry.
 */
class InterceptUrlMapEncodedPathTest {
    private static final String SPEC_NAME = "InterceptUrlMapEncodedPathTest";
    private static final String PASSWORD = "password";
    private static final String ADMIN = "admin";
    private static final String USER = "john";

    private static EmbeddedServer server;
    private static HttpClient httpClient;

    @BeforeAll
    static void start() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("spec.name", SPEC_NAME);
        properties.put("micronaut.security.reject-not-found", StringUtils.FALSE);
        properties.put("micronaut.security.intercept-url-map[0].pattern", "/admin/*");
        properties.put("micronaut.security.intercept-url-map[0].access[0]", "ROLE_ADMIN");
        properties.put("micronaut.security.intercept-url-map[1].pattern", "/users/*/roles");
        properties.put("micronaut.security.intercept-url-map[1].access[0]", "ROLE_ADMIN");
        properties.put("micronaut.security.intercept-url-map[2].pattern", "/*/admin/**");
        properties.put("micronaut.security.intercept-url-map[2].access[0]", "ROLE_ADMIN");
        properties.put("micronaut.security.intercept-url-map[3].pattern", "/books/café");
        properties.put("micronaut.security.intercept-url-map[3].access[0]", "ROLE_ADMIN");
        properties.put("micronaut.security.intercept-url-map[4].pattern", "/**");
        properties.put("micronaut.security.intercept-url-map[4].access[0]", SecurityRule.IS_ANONYMOUS);
        server = ApplicationContext.run(EmbeddedServer.class, properties);
        httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
    }

    @AfterAll
    static void stop() {
        httpClient.close();
        server.close();
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "/admin/1",
        "/admin/x%2Fy",
        "/admin/x%2fy",
        "/admin/%20",
        "/admin/%09",
        "/admin/%00",
        "/admin/%20%09",
        "/admin/jos%C3%A9",
        "/users/1/roles",
        "/users/x%2Fy/roles",
        "/users/%20/roles",
        "/acme/admin/settings",
        "/x%2Fy/admin/settings",
        "/%20/admin/settings",
        "/books/caf%C3%A9"
    })
    void protectedRoutesRejectAnonymousAndUnprivilegedRequests(String path) {
        BlockingHttpClient client = httpClient.toBlocking();
        assertStatus(client, HttpRequest.GET(path), HttpStatus.UNAUTHORIZED);
        assertStatus(client, HttpRequest.GET(path).basicAuth(USER, PASSWORD), HttpStatus.FORBIDDEN);
        assertEquals("ok", client.retrieve(HttpRequest.GET(path).accept(MediaType.TEXT_PLAIN).basicAuth(ADMIN, PASSWORD)));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "/public/1",
        "/public/x%2Fy",
        "/books/other"
    })
    void publicRoutesStayAccessible(String path) {
        BlockingHttpClient client = httpClient.toBlocking();
        assertEquals("ok", client.retrieve(HttpRequest.GET(path).accept(MediaType.TEXT_PLAIN)));
    }

    private static void assertStatus(BlockingHttpClient client, MutableHttpRequest<?> request, HttpStatus expectedStatus) {
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(request.accept(MediaType.TEXT_PLAIN)),
            () -> "GET " + request.getUri() + " should have been rejected");
        assertEquals(expectedStatus, exception.getStatus(), () -> "GET " + request.getUri());
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller
    @Produces(MediaType.TEXT_PLAIN)
    static class RoutesController {
        @Get("/admin/{id}")
        String admin(String id) {
            return "ok";
        }

        @Get("/users/{id}/roles")
        String roles(String id) {
            return "ok";
        }

        @Get("/{tenant}/admin/settings")
        String settings(String tenant) {
            return "ok";
        }

        @Get("/books/{name}")
        String book(String name) {
            return "ok";
        }

        @Get("/public/{id}")
        String publicRoute(String id) {
            return "ok";
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super(Arrays.asList(
                new SuccessAuthenticationScenario(ADMIN, Collections.singletonList("ROLE_ADMIN")),
                new SuccessAuthenticationScenario(USER, Collections.singletonList("ROLE_USER"))));
        }
    }
}
