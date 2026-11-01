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

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.provider.AuthenticationProvider;
import io.micronaut.security.authentication.provider.ExecutorAuthenticationProvider;
import io.micronaut.security.authentication.provider.ReactiveAuthenticationProvider;
import io.micronaut.security.config.AuthenticationStrategy;
import io.micronaut.security.config.SecurityConfiguration;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The response of the highest precedence provider that accepts the credentials must win, no matter how fast the other
 * providers answer.
 */
@Property(name = "spec.name", value = "AuthenticatorProviderOrderTest")
@MicronautTest
class AuthenticatorProviderOrderTest {

    private static final String PASSWORD = "test-fixture-not-a-secret";
    private static final Duration SLOW = Duration.ofMillis(200);

    @Test
    void highestPrecedenceProviderWinsEvenWhenItAnswersLast() {
        try (ApplicationContext ctx = ApplicationContext.run()) {
            ReactiveAuthenticationProvider<Object, String, String> slowHighest = slowProvider(Ordered.HIGHEST, "contractor", "ROLE_CONTRACTOR");
            ReactiveAuthenticationProvider<Object, String, String> fastLowest = fastProvider(Ordered.LOWEST, "contractor", "ROLE_EMPLOYEE");
            Authenticator<Object> authenticator = new Authenticator<>(ctx, List.of(fastLowest, slowHighest), List.of(), new SecurityConfigurationProperties());

            AuthenticationResponse response = authenticate(authenticator);

            assertTrue(response.isAuthenticated());
            assertEquals(List.of("ROLE_CONTRACTOR"), roles(response));
        }
    }

    @Test
    void lowerPrecedenceProviderIsUsedWhenHigherPrecedenceProviderRejects() {
        try (ApplicationContext ctx = ApplicationContext.run()) {
            ReactiveAuthenticationProvider<Object, String, String> rejectingHighest = slowProvider(Ordered.HIGHEST, "somebody-else", "ROLE_CONTRACTOR");
            ReactiveAuthenticationProvider<Object, String, String> acceptingLowest = fastProvider(Ordered.LOWEST, "contractor", "ROLE_EMPLOYEE");
            Authenticator<Object> authenticator = new Authenticator<>(ctx, List.of(acceptingLowest, rejectingHighest), List.of(), new SecurityConfigurationProperties());

            AuthenticationResponse response = authenticate(authenticator);

            assertTrue(response.isAuthenticated());
            assertEquals(List.of("ROLE_EMPLOYEE"), roles(response));
        }
    }

    @Test
    void lowerPrecedenceProvidersAreNotInvokedWhenHigherPrecedenceProviderAccepts() {
        try (ApplicationContext ctx = ApplicationContext.run()) {
            AtomicInteger subscriptions = new AtomicInteger();
            ReactiveAuthenticationProvider<Object, String, String> highest = fastProvider(Ordered.HIGHEST, "contractor", "ROLE_CONTRACTOR");
            ReactiveAuthenticationProvider<Object, String, String> lowest = new OrderedReactiveProvider(Ordered.LOWEST) {
                @Override
                public Publisher<AuthenticationResponse> authenticate(@Nullable Object requestContext, @NonNull AuthenticationRequest<String, String> authenticationRequest) {
                    subscriptions.incrementAndGet();
                    return Mono.just(AuthenticationResponse.success("contractor", List.of("ROLE_EMPLOYEE")));
                }
            };
            Authenticator<Object> authenticator = new Authenticator<>(ctx, List.of(lowest, highest), List.of(), new SecurityConfigurationProperties());

            AuthenticationResponse response = authenticate(authenticator);

            assertEquals(List.of("ROLE_CONTRACTOR"), roles(response));
            assertEquals(0, subscriptions.get());
        }
    }

    @Test
    void authenticationFailsWhenEveryProviderRejects() {
        try (ApplicationContext ctx = ApplicationContext.run()) {
            ReactiveAuthenticationProvider<Object, String, String> highest = slowProvider(Ordered.HIGHEST, "somebody-else", "ROLE_CONTRACTOR");
            ReactiveAuthenticationProvider<Object, String, String> lowest = fastProvider(Ordered.LOWEST, "nobody", "ROLE_EMPLOYEE");
            Authenticator<Object> authenticator = new Authenticator<>(ctx, List.of(lowest, highest), List.of(), new SecurityConfigurationProperties());

            AuthenticationResponse response = authenticate(authenticator);

            assertFalse(response.isAuthenticated());
        }
    }

    @Test
    void allStrategyEvaluatesProvidersInPrecedenceOrder() {
        try (ApplicationContext ctx = ApplicationContext.run()) {
            ReactiveAuthenticationProvider<Object, String, String> slowHighest = slowProvider(Ordered.HIGHEST, "contractor", "ROLE_CONTRACTOR");
            ReactiveAuthenticationProvider<Object, String, String> fastLowest = fastProvider(Ordered.LOWEST, "contractor", "ROLE_EMPLOYEE");
            Authenticator<Object> authenticator = new Authenticator<>(ctx, List.of(fastLowest, slowHighest), List.of(), new AllSecurityConfiguration());

            AuthenticationResponse response = authenticate(authenticator);

            assertTrue(response.isAuthenticated());
            assertEquals(List.of("ROLE_CONTRACTOR"), roles(response));
        }
    }

    @Test
    void imperativeHighestPrecedenceProviderWinsOverReactiveProviderWithDefaultOrder() {
        try (ApplicationContext ctx = ApplicationContext.run()) {
            AuthenticationProvider<Object, String, String> imperativeHighest = new AuthenticationProvider<>() {
                @Override
                public @NonNull AuthenticationResponse authenticate(@Nullable Object requestContext, @NonNull AuthenticationRequest<String, String> authenticationRequest) {
                    return response(authenticationRequest, "contractor", "ROLE_CONTRACTOR");
                }

                @Override
                public int getOrder() {
                    return io.micronaut.core.order.Ordered.HIGHEST_PRECEDENCE;
                }
            };
            ReactiveAuthenticationProvider<Object, String, String> reactiveDefault = new ReactiveAuthenticationProvider<>() {
                @Override
                public Publisher<AuthenticationResponse> authenticate(@Nullable Object requestContext, @NonNull AuthenticationRequest<String, String> authenticationRequest) {
                    return Mono.just(response(authenticationRequest, "contractor", "ROLE_EMPLOYEE"));
                }
            };
            Authenticator<Object> authenticator = new Authenticator<>(ctx, List.of(reactiveDefault), List.of(imperativeHighest), new SecurityConfigurationProperties());

            AuthenticationResponse response = authenticate(authenticator);

            assertTrue(response.isAuthenticated());
            assertEquals(List.of("ROLE_CONTRACTOR"), roles(response));
        }
    }

    @Test
    void blockingImperativeHighestPrecedenceProviderWinsAndLowerPrecedenceProviderIsNotInvoked() {
        try (ApplicationContext ctx = ApplicationContext.run()) {
            assertTrue(ctx.findBean(ExecutorService.class, Qualifiers.byName(TaskExecutors.BLOCKING)).isPresent());
            AtomicInteger lowestInvocations = new AtomicInteger();
            ExecutorAuthenticationProvider<Object, String, String> blockingHighest = new ExecutorAuthenticationProvider<>() {
                @Override
                public @NonNull AuthenticationResponse authenticate(@Nullable Object requestContext, @NonNull AuthenticationRequest<String, String> authenticationRequest) {
                    try {
                        Thread.sleep(SLOW.toMillis());
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    return response(authenticationRequest, "contractor", "ROLE_CONTRACTOR");
                }

                @Override
                public int getOrder() {
                    return io.micronaut.core.order.Ordered.HIGHEST_PRECEDENCE;
                }
            };
            ReactiveAuthenticationProvider<Object, String, String> reactiveLowest = new OrderedReactiveProvider(Ordered.LOWEST) {
                @Override
                public Publisher<AuthenticationResponse> authenticate(@Nullable Object requestContext, @NonNull AuthenticationRequest<String, String> authenticationRequest) {
                    lowestInvocations.incrementAndGet();
                    return Mono.just(response(authenticationRequest, "contractor", "ROLE_EMPLOYEE"));
                }
            };
            Authenticator<Object> authenticator = new Authenticator<>(ctx, List.of(reactiveLowest), List.of(blockingHighest), new SecurityConfigurationProperties());

            AuthenticationResponse response = authenticate(authenticator);

            assertTrue(response.isAuthenticated());
            assertEquals(List.of("ROLE_CONTRACTOR"), roles(response));
            assertEquals(0, lowestInvocations.get());
        }
    }

    @Test
    void allStrategyRejectsWhenAnyProviderRejects() {
        try (ApplicationContext ctx = ApplicationContext.run()) {
            ReactiveAuthenticationProvider<Object, String, String> slowHighest = slowProvider(Ordered.HIGHEST, "contractor", "ROLE_CONTRACTOR");
            ReactiveAuthenticationProvider<Object, String, String> fastLowest = fastProvider(Ordered.LOWEST, "nobody", "ROLE_EMPLOYEE");
            Authenticator<Object> authenticator = new Authenticator<>(ctx, List.of(fastLowest, slowHighest), List.of(), new AllSecurityConfiguration());

            AuthenticationResponse response = authenticate(authenticator);

            assertFalse(response.isAuthenticated());
        }
    }

    @Test
    void basicAuthUsesTheRolesOfTheHighestPrecedenceProvider(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();

        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(HttpRequest.GET("/employees").basicAuth("contractor", PASSWORD)));
        assertEquals(HttpStatus.FORBIDDEN, ex.getStatus());

        assertEquals(HttpStatus.OK, client.exchange(HttpRequest.GET("/employees").basicAuth("employee", PASSWORD)).getStatus());

        ex = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(HttpRequest.GET("/employees").basicAuth("employee", "wrong")));
        assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
    }

    private static AuthenticationResponse authenticate(Authenticator<Object> authenticator) {
        AuthenticationResponse response = Flux.from(authenticator.authenticate(null, new UsernamePasswordCredentials("contractor", PASSWORD))).blockFirst();
        assertNotNull(response);
        return response;
    }

    private static List<String> roles(AuthenticationResponse response) {
        return response.getAuthentication().orElseThrow().getRoles().stream().toList();
    }

    private static ReactiveAuthenticationProvider<Object, String, String> slowProvider(Ordered order, String username, String role) {
        return new OrderedReactiveProvider(order) {
            @Override
            public Publisher<AuthenticationResponse> authenticate(@Nullable Object requestContext, @NonNull AuthenticationRequest<String, String> authenticationRequest) {
                return Mono.delay(SLOW).map(ignored -> response(authenticationRequest, username, role));
            }
        };
    }

    private static ReactiveAuthenticationProvider<Object, String, String> fastProvider(Ordered order, String username, String role) {
        return new OrderedReactiveProvider(order) {
            @Override
            public Publisher<AuthenticationResponse> authenticate(@Nullable Object requestContext, @NonNull AuthenticationRequest<String, String> authenticationRequest) {
                return Mono.just(response(authenticationRequest, username, role));
            }
        };
    }

    private static AuthenticationResponse response(AuthenticationRequest<String, String> authenticationRequest, String username, String role) {
        if (username.equals(authenticationRequest.getIdentity()) && PASSWORD.equals(authenticationRequest.getSecret())) {
            return AuthenticationResponse.success(username, List.of(role));
        }
        return AuthenticationResponse.failure();
    }

    private enum Ordered {
        HIGHEST(io.micronaut.core.order.Ordered.HIGHEST_PRECEDENCE),
        LOWEST(io.micronaut.core.order.Ordered.LOWEST_PRECEDENCE);

        private final int order;

        Ordered(int order) {
            this.order = order;
        }
    }

    private abstract static class OrderedReactiveProvider implements ReactiveAuthenticationProvider<Object, String, String> {
        private final Ordered order;

        OrderedReactiveProvider(Ordered order) {
            this.order = order;
        }

        @Override
        public int getOrder() {
            return order.order;
        }
    }

    private static final class AllSecurityConfiguration extends SecurityConfigurationProperties {
        @Override
        public AuthenticationStrategy getAuthenticationProviderStrategy() {
            return AuthenticationStrategy.ALL;
        }
    }

    @Requires(property = "spec.name", value = "AuthenticatorProviderOrderTest")
    @Controller("/employees")
    static class EmployeesController {

        @Secured("ROLE_EMPLOYEE")
        @Get
        Map<String, Object> index() {
            return Map.of("message", "Hello World");
        }
    }

    /**
     * Highest precedence provider: knows the contractor and limits it to ROLE_CONTRACTOR. It is slower than the
     * directory provider below.
     */
    @Requires(property = "spec.name", value = "AuthenticatorProviderOrderTest")
    @Singleton
    static class ContractorAuthenticationProvider implements ReactiveAuthenticationProvider<HttpRequest<?>, String, String> {

        @Override
        public Publisher<AuthenticationResponse> authenticate(@Nullable HttpRequest<?> requestContext, @NonNull AuthenticationRequest<String, String> authenticationRequest) {
            return Mono.delay(SLOW).map(ignored -> response(authenticationRequest, "contractor", "ROLE_CONTRACTOR"));
        }

        @Override
        public int getOrder() {
            return io.micronaut.core.order.Ordered.HIGHEST_PRECEDENCE;
        }
    }

    /**
     * Lowest precedence provider: a directory which accepts both users and grants ROLE_EMPLOYEE to everybody.
     */
    @Requires(property = "spec.name", value = "AuthenticatorProviderOrderTest")
    @Singleton
    static class DirectoryAuthenticationProvider implements AuthenticationProvider<HttpRequest<?>, String, String> {

        @Override
        public @NonNull AuthenticationResponse authenticate(@Nullable HttpRequest<?> requestContext, @NonNull AuthenticationRequest<String, String> authRequest) {
            if (PASSWORD.equals(authRequest.getSecret()) && List.of("contractor", "employee").contains(authRequest.getIdentity())) {
                return AuthenticationResponse.success(authRequest.getIdentity(), List.of("ROLE_EMPLOYEE"));
            }
            return AuthenticationResponse.failure();
        }

        @Override
        public int getOrder() {
            return io.micronaut.core.order.Ordered.LOWEST_PRECEDENCE;
        }
    }
}
