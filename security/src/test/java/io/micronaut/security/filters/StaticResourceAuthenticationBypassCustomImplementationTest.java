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
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

@Property(name = "spec.name", value = "StaticResourceAuthenticationBypassCustomImplementationTest")
@Property(name = "micronaut.security.filter.static-resource-authentication-bypass", value = "true")
@Property(name = "micronaut.security.intercept-url-map[0].pattern", value = "/**")
@Property(name = "micronaut.security.intercept-url-map[0].access[0]", value = "isAnonymous()")
@MicronautTest
class StaticResourceAuthenticationBypassCustomImplementationTest {

    @Inject
    StaticResourceAuthenticationBypass<HttpRequest<?>> staticResourceAuthenticationBypass;

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
    void customImplementationReplacesTheDefault() {
        assertInstanceOf(CustomStaticResourceAuthenticationBypass.class, staticResourceAuthenticationBypass);
    }

    @Test
    void theSecurityFilterUsesTheCustomImplementation() {
        HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/bypassed"), String.class);

        assertEquals("bypassed", response.body());
        assertEquals(0, authenticationFetcher.invocations.get());
    }

    @Test
    void theSecurityFilterResolvesAuthenticationWhenTheCustomImplementationDoesNotBypass() {
        HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/not-bypassed"), String.class);

        assertEquals("not bypassed", response.body());
        assertEquals(1, authenticationFetcher.invocations.get());
    }

    @Requires(property = "spec.name", value = "StaticResourceAuthenticationBypassCustomImplementationTest")
    @Singleton
    static class CustomStaticResourceAuthenticationBypass implements StaticResourceAuthenticationBypass<HttpRequest<?>> {
        @Override
        public boolean shouldBypass(HttpRequest<?> request) {
            return request.getUri().getPath().equals("/bypassed");
        }
    }

    @Requires(property = "spec.name", value = "StaticResourceAuthenticationBypassCustomImplementationTest")
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

    @Requires(property = "spec.name", value = "StaticResourceAuthenticationBypassCustomImplementationTest")
    @Controller
    static class BypassController {
        @Get("/bypassed")
        String bypassed() {
            return "bypassed";
        }

        @Get("/not-bypassed")
        String notBypassed() {
            return "not bypassed";
        }
    }
}
