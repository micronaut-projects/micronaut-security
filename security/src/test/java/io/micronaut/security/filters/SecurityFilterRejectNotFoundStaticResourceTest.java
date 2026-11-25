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
package io.micronaut.security.filters;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.validator.TokenValidator;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.reactivestreams.Publisher;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * With {@code micronaut.security.reject-not-found=false} a request that matches no route is allowed to proceed so
 * that the server answers 404. A static resource is not a route, but it does exist, so a static resource that no
 * security rule covers must still be rejected instead of being served to an anonymous client.
 */
@Property(name = "spec.name", value = "SecurityFilterRejectNotFoundStaticResourceTest")
@Property(name = "micronaut.security.reject-not-found", value = StringUtils.FALSE)
@Property(name = "micronaut.router.static-resources.exports.mapping", value = "/exports/**")
@Property(name = "micronaut.router.static-resources.exports.paths", value = "classpath:static-resource-authentication-bypass")
@Property(name = "micronaut.security.intercept-url-map[0].pattern", value = "/exports/asset.txt")
@Property(name = "micronaut.security.intercept-url-map[0].access[0]", value = SecurityRule.IS_ANONYMOUS)
@Property(name = "micronaut.security.intercept-url-map[1].pattern", value = "/routed")
@Property(name = "micronaut.security.intercept-url-map[1].access[0]", value = SecurityRule.IS_AUTHENTICATED)
@MicronautTest
class SecurityFilterRejectNotFoundStaticResourceTest {
    private static final String TEST_TOKEN = "test-fixture-not-a-secret";

    @Inject
    @Client("/")
    HttpClient httpClient;

    @ParameterizedTest
    @EnumSource(value = HttpMethod.class, names = {"GET", "HEAD", "POST", "PUT", "DELETE"})
    void staticResourceWithoutRuleIsRejectedForAnonymousRequests(HttpMethod method) {
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> httpClient.toBlocking().exchange(HttpRequest.create(method, "/exports/protected.txt"), String.class),
            () -> method + " /exports/protected.txt should have been rejected");
        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatus(), () -> method + " /exports/protected.txt");
    }

    @Test
    void percentEncodedStaticResourceWithoutRuleIsRejected() {
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> httpClient.toBlocking().exchange(HttpRequest.GET("/exports/%70rotected.txt"), String.class));
        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatus());
    }

    @Test
    void staticResourceWithoutRuleIsForbiddenForAuthenticatedRequests() {
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> httpClient.toBlocking().exchange(authenticated(HttpRequest.GET("/exports/protected.txt")), String.class));
        assertEquals(HttpStatus.FORBIDDEN, exception.getStatus());
    }

    @Test
    void staticResourceAllowedByRuleIsServed() {
        HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/exports/asset.txt"), String.class);
        assertEquals(HttpStatus.OK, response.status());
        assertEquals("static resource", response.body().strip());
    }

    @Test
    void missingStaticResourceIsNotFound() {
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> httpClient.toBlocking().exchange(HttpRequest.GET("/exports/missing.txt"), String.class));
        assertEquals(HttpStatus.NOT_FOUND, exception.getStatus());
    }

    @Test
    void unknownRouteIsNotFound() {
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> httpClient.toBlocking().exchange(HttpRequest.GET("/does-not-exist"), String.class));
        assertEquals(HttpStatus.NOT_FOUND, exception.getStatus());
    }

    @Test
    void routeCoveredByRuleStillRequiresAuthentication() {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(HttpRequest.GET("/routed"), String.class));
        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatus());

        HttpResponse<String> response = client.exchange(authenticated(HttpRequest.GET("/routed")), String.class);
        assertEquals(HttpStatus.OK, response.status());
        assertEquals("routed", response.body());
    }

    private static MutableHttpRequest<?> authenticated(MutableHttpRequest<?> request) {
        return request.bearerAuth(TEST_TOKEN);
    }

    @Requires(property = "spec.name", value = "SecurityFilterRejectNotFoundStaticResourceTest")
    @Controller
    static class RoutedController {
        @Get("/routed")
        String routed() {
            return "routed";
        }
    }

    @Requires(property = "spec.name", value = "SecurityFilterRejectNotFoundStaticResourceTest")
    @Singleton
    static class CustomTokenValidator implements TokenValidator<HttpRequest<?>> {
        @Override
        public @NonNull Publisher<Authentication> validateToken(@NonNull String token,
                                                                @Nullable HttpRequest<?> request) {
            if (token.equals(TEST_TOKEN)) {
                return Publishers.just(Authentication.build("john"));
            }
            return Publishers.empty();
        }
    }
}
