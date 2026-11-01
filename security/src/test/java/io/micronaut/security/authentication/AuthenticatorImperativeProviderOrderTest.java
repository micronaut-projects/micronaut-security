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
package io.micronaut.security.authentication;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.order.Ordered;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.provider.AuthenticationProvider;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * With only non-blocking imperative providers the {@link Authenticator} takes the imperative code path, which relies on
 * the injected provider list being sorted by precedence. The highest precedence provider that accepts the credentials
 * must win and lower precedence providers must not be invoked.
 */
@Property(name = "spec.name", value = "AuthenticatorImperativeProviderOrderTest")
@MicronautTest
class AuthenticatorImperativeProviderOrderTest {

    private static final String PASSWORD = "test-fixture-not-a-secret";
    private static final AtomicInteger DIRECTORY_INVOCATIONS = new AtomicInteger();

    @Test
    void basicAuthUsesTheRolesOfTheHighestPrecedenceImperativeProvider(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();

        DIRECTORY_INVOCATIONS.set(0);
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(HttpRequest.GET("/employees").basicAuth("contractor", PASSWORD)));
        assertEquals(HttpStatus.FORBIDDEN, ex.getStatus());
        assertEquals(0, DIRECTORY_INVOCATIONS.get());

        assertEquals(HttpStatus.OK, client.exchange(HttpRequest.GET("/employees").basicAuth("employee", PASSWORD)).getStatus());
        assertEquals(1, DIRECTORY_INVOCATIONS.get());

        ex = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(HttpRequest.GET("/employees").basicAuth("employee", "wrong")));
        assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
    }

    @Requires(property = "spec.name", value = "AuthenticatorImperativeProviderOrderTest")
    @Controller("/employees")
    static class EmployeesController {

        @Secured("ROLE_EMPLOYEE")
        @Get
        Map<String, Object> index() {
            return Map.of("message", "Hello World");
        }
    }

    /**
     * Lowest precedence provider: a directory which accepts both users and grants ROLE_EMPLOYEE to everybody. Its
     * class name sorts before the contractor provider so that only the precedence order can put it last.
     */
    @Requires(property = "spec.name", value = "AuthenticatorImperativeProviderOrderTest")
    @Singleton
    static class ADirectoryAuthenticationProvider implements AuthenticationProvider<HttpRequest<?>, String, String> {

        @Override
        public @NonNull AuthenticationResponse authenticate(@Nullable HttpRequest<?> requestContext, @NonNull AuthenticationRequest<String, String> authRequest) {
            DIRECTORY_INVOCATIONS.incrementAndGet();
            if (PASSWORD.equals(authRequest.getSecret()) && List.of("contractor", "employee").contains(authRequest.getIdentity())) {
                return AuthenticationResponse.success(authRequest.getIdentity(), List.of("ROLE_EMPLOYEE"));
            }
            return AuthenticationResponse.failure();
        }

        @Override
        public int getOrder() {
            return Ordered.LOWEST_PRECEDENCE;
        }
    }

    /**
     * Highest precedence provider: knows the contractor and limits it to ROLE_CONTRACTOR.
     */
    @Requires(property = "spec.name", value = "AuthenticatorImperativeProviderOrderTest")
    @Singleton
    static class ZContractorAuthenticationProvider implements AuthenticationProvider<HttpRequest<?>, String, String> {

        @Override
        public @NonNull AuthenticationResponse authenticate(@Nullable HttpRequest<?> requestContext, @NonNull AuthenticationRequest<String, String> authRequest) {
            if ("contractor".equals(authRequest.getIdentity()) && PASSWORD.equals(authRequest.getSecret())) {
                return AuthenticationResponse.success("contractor", List.of("ROLE_CONTRACTOR"));
            }
            return AuthenticationResponse.failure();
        }

        @Override
        public int getOrder() {
            return Ordered.HIGHEST_PRECEDENCE;
        }
    }
}
