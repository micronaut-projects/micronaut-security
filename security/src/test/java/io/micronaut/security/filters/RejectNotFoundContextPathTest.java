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
package io.micronaut.security.filters;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.async.publisher.Publishers;
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
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.validator.TokenValidator;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.reactivestreams.Publisher;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * With {@code micronaut.server.context-path} set, a request outside the context path is answered like any other
 * unmatched route: when {@code micronaut.security.reject-not-found} is on, which is the default, 401 for an anonymous
 * request and 403 for an authenticated one; when it is off, 404. The 404 shows that the router does not serve the
 * application outside the context path, whatever security answers.
 */
class RejectNotFoundContextPathTest {
    private static final String SPEC_NAME = "RejectNotFoundContextPathTest";
    private static final String TOKEN = "user";

    @ParameterizedTest(name = "reject-not-found {0}: unmatched requests answer {1} (anonymous) and {2} (authenticated)")
    @MethodSource("configurations")
    void unmatchedRequestsFollowRejectNotFound(@Nullable String rejectNotFound,
                                               HttpStatus anonymousStatus,
                                               HttpStatus authenticatedStatus) {
        Map<String, Object> properties = new HashMap<>();
        properties.put("spec.name", SPEC_NAME);
        properties.put("micronaut.server.context-path", "/foo");
        if (rejectNotFound != null) {
            properties.put("micronaut.security.reject-not-found", rejectNotFound);
        }
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, properties);
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            assertEquals("Home", client.retrieve(HttpRequest.GET("/foo").accept(MediaType.TEXT_PLAIN)));
            for (String path : List.of("/", "/foo/unknown")) {
                assertStatus(client, HttpRequest.GET(path), anonymousStatus);
                assertStatus(client, HttpRequest.GET(path).bearerAuth(TOKEN), authenticatedStatus);
            }
        }
    }

    private static void assertStatus(BlockingHttpClient client, MutableHttpRequest<?> request, HttpStatus expectedStatus) {
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(request.accept(MediaType.TEXT_PLAIN)),
            () -> "GET " + request.getUri() + " should not have been served");
        assertEquals(expectedStatus, exception.getStatus(), () -> "GET " + request.getUri());
    }

    private static Stream<Arguments> configurations() {
        return Stream.of(
            Arguments.of(null, HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN),
            Arguments.of(StringUtils.FALSE, HttpStatus.NOT_FOUND, HttpStatus.NOT_FOUND)
        );
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller
    static class HomeController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String index() {
            return "Home";
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class CustomTokenValidator implements TokenValidator<HttpRequest<?>> {
        @Override
        public @NonNull Publisher<Authentication> validateToken(@NonNull String token,
                                                                @Nullable HttpRequest<?> request) {
            return token.equals(TOKEN) ? Publishers.just(Authentication.build("john")) : Publishers.empty();
        }
    }
}
