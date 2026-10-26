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
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.MockAuthenticationProvider;
import io.micronaut.security.SuccessAuthenticationScenario;
import jakarta.inject.Singleton;
import io.micronaut.core.annotation.Nullable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * An intercept URL map entry for the application root must keep protecting the root route
 * when {@code micronaut.server.context-path} is set and the patterns are prepended with the
 * context path, for both {@code /ctx} and {@code /ctx/}.
 */
class InterceptUrlMapContextPathRootTest {
    private static final String SPEC_NAME = "InterceptUrlMapContextPathRootTest";
    private static final String USERNAME = "user";
    private static final String PASSWORD = "password";

    @ParameterizedTest(name = "root pattern {0} with context path {1}: anonymous requests")
    @MethodSource("rootPatterns")
    void anonymousRequestsToRootAreRejected(String rootPattern, String contextPath) {
        withServer(rootPattern, contextPath, (client, prefix) -> {
            assertStatus(client, HttpRequest.GET(prefix), HttpStatus.UNAUTHORIZED);
            assertStatus(client, HttpRequest.GET(prefix + "/"), HttpStatus.UNAUTHORIZED);
            assertStatus(client, HttpRequest.POST(prefix, "body"), HttpStatus.UNAUTHORIZED);
            assertStatus(client, HttpRequest.POST(prefix + "/", "body"), HttpStatus.UNAUTHORIZED);
            assertStatus(client, HttpRequest.GET(prefix + "/invoices"), HttpStatus.UNAUTHORIZED);
            assertEquals("public", client.retrieve(HttpRequest.GET(prefix + "/public/docs").accept(MediaType.TEXT_PLAIN)));
        });
    }

    @ParameterizedTest(name = "root pattern {0} with context path {1}: authenticated requests")
    @MethodSource("rootPatterns")
    void authenticatedRequestsToRootAreAllowed(String rootPattern, String contextPath) {
        withServer(rootPattern, contextPath, (client, prefix) -> {
            assertEquals("root", retrieveAuthenticated(client, HttpRequest.GET(prefix)));
            assertEquals("root", retrieveAuthenticated(client, HttpRequest.GET(prefix + "/")));
            assertEquals("created", retrieveAuthenticated(client, HttpRequest.POST(prefix, "body")));
            assertEquals("invoices", retrieveAuthenticated(client, HttpRequest.GET(prefix + "/invoices")));
            assertEquals("public", retrieveAuthenticated(client, HttpRequest.GET(prefix + "/public/docs")));
        });
    }

    private static Stream<Arguments> rootPatterns() {
        return Stream.of(
            Arguments.of("/", null),
            Arguments.of("/", "/portal"),
            Arguments.of("/", "portal"),
            Arguments.of("/", "/portal/"),
            Arguments.of("/*", null),
            Arguments.of("/*", "/portal"),
            Arguments.of("/*", "portal")
        );
    }

    private static void withServer(String rootPattern, @Nullable String contextPath, ServerTest test) {
        Map<String, Object> properties = new HashMap<>();
        properties.put("spec.name", SPEC_NAME);
        properties.put("micronaut.security.reject-not-found", StringUtils.FALSE);
        properties.put("micronaut.security.intercept-url-map-prepend-pattern-with-context-path", StringUtils.TRUE);
        properties.put("micronaut.security.intercept-url-map[0].pattern", rootPattern);
        properties.put("micronaut.security.intercept-url-map[0].access[0]", SecurityRule.IS_AUTHENTICATED);
        properties.put("micronaut.security.intercept-url-map[1].pattern", "/invoices");
        properties.put("micronaut.security.intercept-url-map[1].access[0]", SecurityRule.IS_AUTHENTICATED);
        properties.put("micronaut.security.intercept-url-map[2].pattern", "/**");
        properties.put("micronaut.security.intercept-url-map[2].access[0]", SecurityRule.IS_ANONYMOUS);
        if (contextPath != null) {
            properties.put("micronaut.server.context-path", contextPath);
        }
        String prefix = contextPath == null ? "" : "/" + StringUtils.trimLeadingCharacter(contextPath, '/').replaceAll("/+$", "");
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, properties);
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            test.run(httpClient.toBlocking(), prefix);
        }
    }

    private static String retrieveAuthenticated(BlockingHttpClient client, MutableHttpRequest<?> request) {
        return client.retrieve(request.accept(MediaType.TEXT_PLAIN).basicAuth(USERNAME, PASSWORD));
    }

    private static void assertStatus(BlockingHttpClient client, MutableHttpRequest<?> request, HttpStatus expectedStatus) {
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(request.accept(MediaType.TEXT_PLAIN)),
            () -> request.getMethod() + " " + request.getUri() + " should have been rejected");
        assertEquals(expectedStatus, exception.getStatus(), () -> request.getMethod() + " " + request.getUri());
    }

    @FunctionalInterface
    private interface ServerTest {
        void run(BlockingHttpClient client, String prefix);
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller
    static class RootController {
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String index() {
            return "root";
        }

        @Produces(MediaType.TEXT_PLAIN)
        @Post
        String create() {
            return "created";
        }

        @Produces(MediaType.TEXT_PLAIN)
        @Get("/invoices")
        String invoices() {
            return "invoices";
        }

        @Produces(MediaType.TEXT_PLAIN)
        @Get("/public/docs")
        String docs() {
            return "public";
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super(Collections.singletonList(new SuccessAuthenticationScenario(USERNAME, PASSWORD)));
        }
    }
}
