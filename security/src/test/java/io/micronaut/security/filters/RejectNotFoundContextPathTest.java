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
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * With {@code micronaut.server.context-path} set, an anonymous request outside the context path is answered like any
 * other unmatched route: 401 when {@code micronaut.security.reject-not-found} is on, which is the default, and 404 when
 * it is off. The 404 shows that the router does not serve the application outside the context path, whatever security
 * answers.
 */
class RejectNotFoundContextPathTest {
    private static final String SPEC_NAME = "RejectNotFoundContextPathTest";

    @ParameterizedTest(name = "reject-not-found {0}: unmatched requests answer {1}")
    @MethodSource("configurations")
    void unmatchedRequestsFollowRejectNotFound(@Nullable String rejectNotFound, HttpStatus expectedStatus) {
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
                HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
                    () -> client.exchange(HttpRequest.GET(path).accept(MediaType.TEXT_PLAIN)),
                    () -> "GET " + path + " should not have been served");
                assertEquals(expectedStatus, exception.getStatus(), () -> "GET " + path);
            }
        }
    }

    private static Stream<Arguments> configurations() {
        return Stream.of(
            Arguments.of(null, HttpStatus.UNAUTHORIZED),
            Arguments.of(StringUtils.FALSE, HttpStatus.NOT_FOUND)
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
}
