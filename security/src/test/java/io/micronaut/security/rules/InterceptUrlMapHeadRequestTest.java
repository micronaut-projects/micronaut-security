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
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Head;
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
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * A {@code @Get} route and a static resource also answer HEAD requests, so an intercept URL map entry restricted
 * to GET must not be skipped by sending the same request as HEAD.
 */
class InterceptUrlMapHeadRequestTest {
    private static final String SPEC_NAME = "InterceptUrlMapHeadRequestTest";
    private static final String USER = "john";
    private static final String PASSWORD = "password";

    private static EmbeddedServer server;
    private static HttpClient httpClient;

    @BeforeAll
    static void start() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("micronaut.security.reject-not-found", StringUtils.FALSE);
        properties.put("spec.name", SPEC_NAME);
        properties.put("micronaut.router.static-resources.assets.mapping", "/assets/**");
        properties.put("micronaut.router.static-resources.assets.paths", "classpath:static-resource-authentication-bypass");
        properties.put("micronaut.security.intercept-url-map[0].pattern", "/admin/secret");
        properties.put("micronaut.security.intercept-url-map[0].http-method", "GET");
        properties.put("micronaut.security.intercept-url-map[0].access[0]", SecurityRule.IS_AUTHENTICATED);
        properties.put("micronaut.security.intercept-url-map[1].pattern", "/assets/protected.txt");
        properties.put("micronaut.security.intercept-url-map[1].http-method", "GET");
        properties.put("micronaut.security.intercept-url-map[1].access[0]", SecurityRule.IS_AUTHENTICATED);
        properties.put("micronaut.security.intercept-url-map[2].pattern", "/admin/explicit-head");
        properties.put("micronaut.security.intercept-url-map[2].http-method", "GET");
        properties.put("micronaut.security.intercept-url-map[2].access[0]", SecurityRule.IS_AUTHENTICATED);
        properties.put("micronaut.security.intercept-url-map[3].pattern", "/admin/explicit-head");
        properties.put("micronaut.security.intercept-url-map[3].http-method", "HEAD");
        properties.put("micronaut.security.intercept-url-map[3].access[0]", SecurityRule.IS_ANONYMOUS);
        properties.put("micronaut.security.intercept-url-map[4].pattern", "/admin/no-head-route");
        properties.put("micronaut.security.intercept-url-map[4].http-method", "GET");
        properties.put("micronaut.security.intercept-url-map[4].access[0]", SecurityRule.IS_AUTHENTICATED);
        properties.put("micronaut.security.intercept-url-map[5].pattern", "/reports/**");
        properties.put("micronaut.security.intercept-url-map[5].http-method", "GET");
        properties.put("micronaut.security.intercept-url-map[5].access[0]", SecurityRule.IS_ANONYMOUS);
        properties.put("micronaut.security.intercept-url-map[6].pattern", "/reports/**");
        properties.put("micronaut.security.intercept-url-map[6].access[0]", SecurityRule.IS_AUTHENTICATED);
        properties.put("micronaut.security.intercept-url-map[7].pattern", "/**");
        properties.put("micronaut.security.intercept-url-map[7].access[0]", SecurityRule.IS_ANONYMOUS);
        server = ApplicationContext.run(EmbeddedServer.class, properties);
        httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
    }

    @AfterAll
    static void stop() {
        httpClient.close();
        server.close();
    }

    @ParameterizedTest
    @MethodSource("protectedPaths")
    void getEntryAlsoProtectsHeadRequests(HttpMethod method, String path) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(request(method, path)),
            () -> method + " " + path + " should have been rejected");
        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatus(), () -> method + " " + path);
    }

    @ParameterizedTest
    @MethodSource("protectedPaths")
    void authenticatedRequestsAreServed(HttpMethod method, String path) {
        HttpResponse<?> response = httpClient.toBlocking().exchange(request(method, path).basicAuth(USER, PASSWORD));
        assertEquals(HttpStatus.OK, response.status(), () -> method + " " + path);
    }

    @ParameterizedTest
    @MethodSource("publicPaths")
    void anonymousRequestsAreServed(HttpMethod method, String path) {
        HttpResponse<?> response = httpClient.toBlocking().exchange(request(method, path));
        assertEquals(HttpStatus.OK, response.status(), () -> method + " " + path);
    }

    @ParameterizedTest
    @MethodSource("unroutedPaths")
    void getEntryAlsoProtectsUnroutedRequestsOfOtherMethods(HttpMethod method, String path) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpClientResponseException anonymous = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(request(method, path)),
            () -> method + " " + path + " should have been rejected");
        assertEquals(HttpStatus.UNAUTHORIZED, anonymous.getStatus(), () -> "anonymous " + method + " " + path);

        // once authenticated, the request reaches the router, which has no route for this method
        HttpClientResponseException authenticated = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(request(method, path).basicAuth(USER, PASSWORD)),
            () -> method + " " + path + " should not have been routed");
        assertEquals(HttpStatus.METHOD_NOT_ALLOWED, authenticated.getStatus(), () -> "authenticated " + method + " " + path);
    }

    private static Stream<Arguments> unroutedPaths() {
        return Stream.of(
            // only GET and HEAD routes exist for /admin/secret
            Arguments.of(HttpMethod.POST, "/admin/secret"),
            Arguments.of(HttpMethod.DELETE, "/admin/secret"),
            // @Get(headRoute = false) declares no HEAD route, so the HEAD request is unrouted
            Arguments.of(HttpMethod.HEAD, "/admin/no-head-route"));
    }

    private static Stream<Arguments> protectedPaths() {
        return Stream.of(
            Arguments.of(HttpMethod.GET, "/admin/secret"),
            Arguments.of(HttpMethod.HEAD, "/admin/secret"),
            Arguments.of(HttpMethod.GET, "/assets/protected.txt"),
            Arguments.of(HttpMethod.HEAD, "/assets/protected.txt"),
            Arguments.of(HttpMethod.POST, "/assets/protected.txt"),
            Arguments.of(HttpMethod.PUT, "/assets/protected.txt"),
            Arguments.of(HttpMethod.DELETE, "/assets/protected.txt"),
            Arguments.of(HttpMethod.GET, "/admin/explicit-head"),
            Arguments.of(HttpMethod.GET, "/admin/no-head-route"),
            // an explicitly declared @Head method keeps the policy of the method-less entry, not the public GET policy
            Arguments.of(HttpMethod.HEAD, "/reports/status"));
    }

    private static Stream<Arguments> publicPaths() {
        return Stream.of(
            Arguments.of(HttpMethod.GET, "/admin/public"),
            Arguments.of(HttpMethod.HEAD, "/admin/public"),
            Arguments.of(HttpMethod.GET, "/assets/asset.txt"),
            Arguments.of(HttpMethod.HEAD, "/assets/asset.txt"),
            Arguments.of(HttpMethod.HEAD, "/admin/explicit-head"),
            Arguments.of(HttpMethod.GET, "/reports/status"),
            Arguments.of(HttpMethod.GET, "/reports/summary"),
            // the implicit HEAD route of a @Get method inherits the public GET policy
            Arguments.of(HttpMethod.HEAD, "/reports/summary"));
    }

    private static MutableHttpRequest<?> request(HttpMethod method, String path) {
        return HttpRequest.create(method, path).accept(MediaType.TEXT_PLAIN);
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller("/admin")
    static class AdminController {
        @Produces(MediaType.TEXT_PLAIN)
        @Get("/secret")
        String secret() {
            return "secret";
        }

        @Produces(MediaType.TEXT_PLAIN)
        @Get("/public")
        String publicResource() {
            return "public";
        }

        // on Micronaut 3 an implicit HEAD route next to an explicit @Head route for the same URI makes the router
        // answer 400 (more than one route matched), so the @Get method declares no HEAD route
        @Produces(MediaType.TEXT_PLAIN)
        @Get(value = "/explicit-head", headRoute = false)
        String explicitHead() {
            return "explicit head";
        }

        @Produces(MediaType.TEXT_PLAIN)
        @Head("/explicit-head")
        HttpResponse<?> explicitHeadRoute() {
            return HttpResponse.ok();
        }

        @Produces(MediaType.TEXT_PLAIN)
        @Get(value = "/no-head-route", headRoute = false)
        String noHeadRoute() {
            return "no head route";
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller("/reports")
    static class ReportsController {
        @Produces(MediaType.TEXT_PLAIN)
        @Get(value = "/status", headRoute = false)
        String status() {
            return "status";
        }

        @Produces(MediaType.TEXT_PLAIN)
        @Head("/status")
        HttpResponse<?> statusHead() {
            return HttpResponse.ok();
        }

        @Produces(MediaType.TEXT_PLAIN)
        @Get("/summary")
        String summary() {
            return "summary";
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super(Collections.singletonList(new SuccessAuthenticationScenario(USER)));
        }
    }
}
