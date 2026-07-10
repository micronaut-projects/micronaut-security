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

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.validator.TokenValidator;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.reactivestreams.Publisher;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Property(name = "micronaut.security.reject-not-found", value = StringUtils.FALSE)
@Property(name = "spec.name", value = "InterceptUrlMapTrailingSlashTest")
@Property(name = "micronaut.security.intercept-url-map[0].pattern", value = "/admin/secret")
@Property(name = "micronaut.security.intercept-url-map[0].access[0]", value = "isAuthenticated()")
@Property(name = "micronaut.security.intercept-url-map[1].pattern", value = "/**")
@Property(name = "micronaut.security.intercept-url-map[1].access[0]", value = "isAnonymous()")
@MicronautTest
class InterceptUrlMapTrailingSlashTest {

    @Inject
    @Client("/")
    HttpClient httpClient;

    @ParameterizedTest
    @MethodSource("requestPaths")
    void exactInterceptUrlMapDoesNotAuthorizeRoutingVariants(String path,
                                                              HttpStatus expectedStatus) {
        BlockingHttpClient client = httpClient.toBlocking();
        assertStatus(client, path, expectedStatus);
    }

    @ParameterizedTest
    @MethodSource("authorizedRequestPaths")
    void authorizedRequest(String path) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = HttpRequest.GET(path)
            .accept(MediaType.TEXT_PLAIN)
            .bearerAuth("XXX");
        assertDoesNotThrow(() -> client.exchange(request));
    }

    private static Stream<Arguments> requestPaths() {
        return Stream.of(
            Arguments.of("/admin/secret", HttpStatus.UNAUTHORIZED),
            Arguments.of("/admin/secret/", HttpStatus.UNAUTHORIZED)
        );
    }

    private static Stream<String> authorizedRequestPaths() {
        return Stream.of(
            "/admin/secret",
            "/admin/secret/");
    }

    private static void assertStatus(BlockingHttpClient client, String path, HttpStatus expectedStatus) {
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(HttpRequest.GET(path).accept(MediaType.TEXT_PLAIN)));
        assertEquals(expectedStatus, exception.getStatus());
    }

    @Requires(property = "spec.name", value = "InterceptUrlMapTrailingSlashTest")
        @Controller("/admin")
        static class AdminController {
            @Produces(MediaType.TEXT_PLAIN)
            @Get("/secret")
            String secret() {
                return "secret";
            }
        }

    @Requires(property = "spec.name", value = "InterceptUrlMapTrailingSlashTest")
    @Singleton
    static class CustomTokenValidator implements TokenValidator<HttpRequest<?>> {
        @Override
        public @NonNull Publisher<Authentication> validateToken(@NonNull String token,
                                                                @Nullable HttpRequest<?> request) {
            if (token.equals("XXX")) {
                return Publishers.just(Authentication.build("john"));
            }
            return Publishers.empty();
        }
    }
}
