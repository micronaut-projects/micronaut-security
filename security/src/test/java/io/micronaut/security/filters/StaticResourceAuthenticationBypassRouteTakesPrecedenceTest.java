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

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Property(name = "spec.name", value = "StaticResourceAuthenticationBypassRouteTakesPrecedenceTest")
@Property(name = "micronaut.router.static-resources.default.mapping", value = "/assets/**")
@Property(name = "micronaut.router.static-resources.default.paths", value = "classpath:static-resource-authentication-bypass")
@Property(name = "micronaut.security.filter.static-resource-authentication-bypass", value = "true")
@Property(name = "micronaut.security.intercept-url-map[0].pattern", value = "/assets/asset.txt")
@Property(name = "micronaut.security.intercept-url-map[0].access[0]", value = "isAuthenticated()")
@Property(name = "micronaut.security.intercept-url-map[1].pattern", value = "/assets/**")
@Property(name = "micronaut.security.intercept-url-map[1].access[0]", value = "isAnonymous()")
@MicronautTest
class StaticResourceAuthenticationBypassRouteTakesPrecedenceTest {

    @Inject
    @Client("/")
    HttpClient httpClient;

    @Inject
    CountingAuthenticationFetcher authenticationFetcher;

    @BeforeEach
    void resetAuthenticationFetcher() {
        authenticationFetcher.invocations.set(0);
    }

    @Test
    void authenticationIsResolvedWhenARouteShadowsAStaticResource() {
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> httpClient.toBlocking().exchange(HttpRequest.GET("/assets/asset.txt"), String.class));

        assertEquals(401, exception.getStatus().getCode());
        assertEquals(1, authenticationFetcher.invocations.get());
    }

    @Requires(property = "spec.name", value = "StaticResourceAuthenticationBypassRouteTakesPrecedenceTest")
    @Singleton
    static class CountingAuthenticationFetcher implements AuthenticationFetcher<HttpRequest<?>> {
        private final AtomicInteger invocations = new AtomicInteger();

        @Override
        public Publisher<Authentication> fetchAuthentication(HttpRequest<?> request) {
            invocations.incrementAndGet();
            return Publishers.empty();
        }

        @Override
        public int getOrder() {
            return 1000;
        }
    }

    @Requires(property = "spec.name", value = "StaticResourceAuthenticationBypassRouteTakesPrecedenceTest")
    @Controller
    static class ShadowingController {
        @Get("/assets/asset.txt")
        String asset() {
            return "from the controller";
        }
    }
}
