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
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.order.Ordered;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.config.AuthenticationStrategy;
import io.micronaut.security.config.SecurityConfigurationProperties;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The response of the highest precedence provider that accepts the credentials must win, no matter how fast the other
 * providers answer. On this branch {@link AuthenticationProvider} does not extend {@link Ordered}: the {@link Authenticator}
 * sorts the providers which implement {@link Ordered} by precedence and evaluates the others afterwards, in the order it
 * receives them.
 */
class AuthenticatorProviderOrderTest {

    private static final String PASSWORD = "test-fixture-not-a-secret";
    private static final Duration SLOW = Duration.ofMillis(200);

    @Test
    void highestPrecedenceProviderWinsEvenWhenItAnswersLast() {
        AuthenticationProvider slowHighest = slowProvider("contractor", "ROLE_CONTRACTOR");
        AuthenticationProvider fastLowest = fastProvider("contractor", "ROLE_EMPLOYEE");
        Authenticator authenticator = new Authenticator(Arrays.asList(fastLowest, slowHighest), new SecurityConfigurationProperties());
        AuthenticationResponse response = authenticate(authenticator);
        assertTrue(response.isAuthenticated());
        assertEquals(Collections.singletonList("ROLE_CONTRACTOR"), roles(response));
    }

    @Test
    void lowerPrecedenceProviderIsUsedWhenHigherPrecedenceProviderRejects() {
        AuthenticationProvider rejectingHighest = slowProvider("somebody-else", "ROLE_CONTRACTOR");
        AuthenticationProvider acceptingLowest = fastProvider("contractor", "ROLE_EMPLOYEE");
        Authenticator authenticator = new Authenticator(Arrays.asList(acceptingLowest, rejectingHighest), new SecurityConfigurationProperties());
        AuthenticationResponse response = authenticate(authenticator);
        assertTrue(response.isAuthenticated());
        assertEquals(Collections.singletonList("ROLE_EMPLOYEE"), roles(response));
    }

    @Test
    void lowerPrecedenceProvidersAreNotInvokedWhenHigherPrecedenceProviderAccepts() {
        AtomicInteger subscriptions = new AtomicInteger();
        AuthenticationProvider highest = new OrderedProvider(Ordered.HIGHEST_PRECEDENCE) {
            @Override
            public Publisher<AuthenticationResponse> authenticate(@Nullable HttpRequest<?> httpRequest, @NonNull AuthenticationRequest<?, ?> authenticationRequest) {
                return Mono.just(response(authenticationRequest, "contractor", "ROLE_CONTRACTOR"));
            }
        };
        AuthenticationProvider lowest = new OrderedProvider(Ordered.LOWEST_PRECEDENCE) {
            @Override
            public Publisher<AuthenticationResponse> authenticate(@Nullable HttpRequest<?> httpRequest, @NonNull AuthenticationRequest<?, ?> authenticationRequest) {
                subscriptions.incrementAndGet();
                return Mono.just(AuthenticationResponse.success("contractor", Collections.singletonList("ROLE_EMPLOYEE")));
            }
        };
        Authenticator authenticator = new Authenticator(Arrays.asList(lowest, highest), new SecurityConfigurationProperties());
        AuthenticationResponse response = authenticate(authenticator);
        assertEquals(Collections.singletonList("ROLE_CONTRACTOR"), roles(response));
        assertEquals(0, subscriptions.get());
    }

    @Test
    void authenticationFailsWhenEveryProviderRejects() {
        AuthenticationProvider highest = slowProvider("somebody-else", "ROLE_CONTRACTOR");
        AuthenticationProvider lowest = fastProvider("nobody", "ROLE_EMPLOYEE");
        Authenticator authenticator = new Authenticator(Arrays.asList(lowest, highest), new SecurityConfigurationProperties());
        AuthenticationResponse response = authenticate(authenticator);
        assertFalse(response.isAuthenticated());
    }

    @Test
    void allStrategyEvaluatesProvidersInPrecedenceOrder() {
        AuthenticationProvider slowHighest = slowProvider("contractor", "ROLE_CONTRACTOR");
        AuthenticationProvider fastLowest = fastProvider("contractor", "ROLE_EMPLOYEE");
        Authenticator authenticator = new Authenticator(Arrays.asList(fastLowest, slowHighest), new AllSecurityConfiguration());
        AuthenticationResponse response = authenticate(authenticator);
        assertTrue(response.isAuthenticated());
        assertEquals(Collections.singletonList("ROLE_CONTRACTOR"), roles(response));
    }

    @Test
    void allStrategyRejectsWhenAnyProviderRejects() {
        AuthenticationProvider slowHighest = slowProvider("contractor", "ROLE_CONTRACTOR");
        AuthenticationProvider fastLowest = fastProvider("nobody", "ROLE_EMPLOYEE");
        Authenticator authenticator = new Authenticator(Arrays.asList(fastLowest, slowHighest), new AllSecurityConfiguration());
        AuthenticationResponse response = authenticate(authenticator);
        assertFalse(response.isAuthenticated());
    }

    /**
     * The slow {@link ContractorAuthenticationProvider} with {@link Ordered#HIGHEST_PRECEDENCE} must win over the fast
     * {@link DirectoryAuthenticationProvider} with {@link Ordered#LOWEST_PRECEDENCE}, whatever order the bean context injects
     * them in, so the contractor only gets ROLE_CONTRACTOR.
     */
    @Test
    void basicAuthUsesTheRolesOfTheHighestPrecedenceProvider() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Collections.singletonMap("spec.name", "AuthenticatorProviderOrderTest"));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            assertEquals(2, server.getApplicationContext().getBeansOfType(AuthenticationProvider.class).size());

            BlockingHttpClient client = httpClient.toBlocking();
            HttpClientResponseException ex = assertThrows(HttpClientResponseException.class,
                () -> client.exchange(HttpRequest.GET("/employees").basicAuth("contractor", PASSWORD)));
            assertEquals(HttpStatus.FORBIDDEN, ex.getStatus());
            assertEquals(HttpStatus.OK, client.exchange(HttpRequest.GET("/employees").basicAuth("employee", PASSWORD)).getStatus());
            ex = assertThrows(HttpClientResponseException.class,
                () -> client.exchange(HttpRequest.GET("/employees").basicAuth("employee", "wrong")));
            assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
        }
    }

    private static AuthenticationResponse authenticate(Authenticator authenticator) {
        AuthenticationResponse response = Flux.from(authenticator.authenticate(null, new UsernamePasswordCredentials("contractor", PASSWORD))).blockFirst();
        assertNotNull(response);
        return response;
    }

    private static List<String> roles(AuthenticationResponse response) {
        return new ArrayList<>(response.getAuthentication().get().getRoles());
    }

    private static AuthenticationProvider slowProvider(String username, String role) {
        return new OrderedProvider(Ordered.HIGHEST_PRECEDENCE) {
            @Override
            public Publisher<AuthenticationResponse> authenticate(@Nullable HttpRequest<?> httpRequest, @NonNull AuthenticationRequest<?, ?> authenticationRequest) {
                return Mono.delay(SLOW).map(ignored -> response(authenticationRequest, username, role));
            }
        };
    }

    private static AuthenticationProvider fastProvider(String username, String role) {
        return new OrderedProvider(Ordered.LOWEST_PRECEDENCE) {
            @Override
            public Publisher<AuthenticationResponse> authenticate(@Nullable HttpRequest<?> httpRequest, @NonNull AuthenticationRequest<?, ?> authenticationRequest) {
                return Mono.just(response(authenticationRequest, username, role));
            }
        };
    }

    private abstract static class OrderedProvider implements AuthenticationProvider, Ordered {
        private final int order;

        OrderedProvider(int order) {
            this.order = order;
        }

        @Override
        public int getOrder() {
            return order;
        }
    }

    private static AuthenticationResponse response(AuthenticationRequest<?, ?> authenticationRequest, String username, String role) {
        if (username.equals(authenticationRequest.getIdentity()) && PASSWORD.equals(authenticationRequest.getSecret())) {
            return AuthenticationResponse.success(username, Collections.singletonList(role));
        }
        return AuthenticationResponse.failure();
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
            return Collections.singletonMap("message", "Hello World");
        }
    }

    /**
     * Highest precedence provider: knows the contractor and limits it to ROLE_CONTRACTOR. It is slower than the
     * directory provider below.
     */
    @Requires(property = "spec.name", value = "AuthenticatorProviderOrderTest")
    @Singleton
    static class ContractorAuthenticationProvider implements AuthenticationProvider, Ordered {
        @Override
        public Publisher<AuthenticationResponse> authenticate(@Nullable HttpRequest<?> httpRequest, @NonNull AuthenticationRequest<?, ?> authenticationRequest) {
            return Mono.delay(SLOW).map(ignored -> response(authenticationRequest, "contractor", "ROLE_CONTRACTOR"));
        }

        @Override
        public int getOrder() {
            return Ordered.HIGHEST_PRECEDENCE;
        }
    }

    /**
     * Lowest precedence provider: a directory which accepts both users and grants ROLE_EMPLOYEE to everybody.
     */
    @Requires(property = "spec.name", value = "AuthenticatorProviderOrderTest")
    @Singleton
    static class DirectoryAuthenticationProvider implements AuthenticationProvider, Ordered {
        @Override
        public Publisher<AuthenticationResponse> authenticate(@Nullable HttpRequest<?> httpRequest, @NonNull AuthenticationRequest<?, ?> authenticationRequest) {
            if (PASSWORD.equals(authenticationRequest.getSecret()) && Arrays.asList("contractor", "employee").contains(authenticationRequest.getIdentity())) {
                return Mono.just(AuthenticationResponse.success(authenticationRequest.getIdentity().toString(), Collections.singletonList("ROLE_EMPLOYEE")));
            }
            return Mono.just(AuthenticationResponse.failure());
        }

        @Override
        public int getOrder() {
            return Ordered.LOWEST_PRECEDENCE;
        }
    }
}
