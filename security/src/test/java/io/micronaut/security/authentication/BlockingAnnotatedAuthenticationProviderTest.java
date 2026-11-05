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
import io.micronaut.core.annotation.Blocking;
import io.micronaut.http.HttpRequest;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.security.authentication.provider.HttpRequestAuthenticationProvider;
import io.micronaut.security.authentication.provider.HttpRequestExecutorAuthenticationProvider;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import io.micronaut.core.annotation.Nullable;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * An {@link HttpRequestAuthenticationProvider} whose {@code authenticate} method, or whose class, is annotated with
 * {@link Blocking} runs on the {@code blocking} executor, as documented, and an executor provider with a null or empty
 * executor name falls back to it too.
 */
@Property(name = "spec.name", value = "BlockingAnnotatedAuthenticationProviderTest")
@MicronautTest(startApplication = false)
class BlockingAnnotatedAuthenticationProviderTest {

    private static final List<String> PREFIXES = List.of(TaskExecutors.VIRTUAL + "-executor", TaskExecutors.IO + "-executor");

    @Test
    void blockingAnnotatedProviderAcceptsOnBlockingExecutor(Authenticator<HttpRequest<?>> authenticator,
                                                            AnnotatedProvider<?> provider) {
        provider.thread.set(null);
        AuthenticationResponse response = Mono.from(authenticator.authenticate(HttpRequest.GET("/"),
            new UsernamePasswordCredentials("lebowski", "test-fixture-not-a-secret"))).block();
        assertNotNull(response);
        assertTrue(response.isAuthenticated());
        assertOnBlocking(provider.thread.get());
    }

    @Test
    void blockingAnnotatedProviderRejectsOnBlockingExecutor(Authenticator<HttpRequest<?>> authenticator,
                                                            AnnotatedProvider<?> provider) {
        provider.thread.set(null);
        AuthenticationResponse response = Mono.from(authenticator.authenticate(HttpRequest.GET("/"),
            new UsernamePasswordCredentials("smoky", "wrong-test-fixture-not-a-secret"))).block();
        assertNotNull(response);
        assertFalse(response.isAuthenticated());
        assertOnBlocking(provider.thread.get());
    }

    @Test
    void typeLevelBlockingAnnotatedProviderRunsOnBlockingExecutor(Authenticator<HttpRequest<?>> authenticator,
                                                                  TypeAnnotatedProvider<?> provider) {
        provider.thread.set(null);
        AuthenticationResponse response = Mono.from(authenticator.authenticate(HttpRequest.GET("/"),
            new UsernamePasswordCredentials("smoky", "wrong-test-fixture-not-a-secret"))).block();
        assertNotNull(response);
        assertFalse(response.isAuthenticated());
        assertOnBlocking(provider.thread.get());
    }

    @Test
    void nullAndEmptyExecutorNamesFallBackToBlockingExecutor(Authenticator<HttpRequest<?>> authenticator,
                                                             NullNameProvider<?> nullName,
                                                             EmptyNameProvider<?> emptyName) {
        nullName.thread.set(null);
        emptyName.thread.set(null);
        Mono.from(authenticator.authenticate(HttpRequest.GET("/"),
            new UsernamePasswordCredentials("smoky", "wrong-test-fixture-not-a-secret"))).block();
        assertOnBlocking(nullName.thread.get());
        assertOnBlocking(emptyName.thread.get());
    }

    @Test
    void adapterDelegatesOrder(AnnotatedProvider<?> provider) {
        assertEquals(provider.getOrder(), new AuthenticationProviderAdapter<>(provider).getOrder());
        assertEquals(-42, new AuthenticationProviderAdapter<>(provider).getOrder());
    }

    private static void assertOnBlocking(String threadName) {
        assertNotNull(threadName, "provider was not invoked");
        assertNotEquals(Thread.currentThread().getName(), threadName);
        assertTrue(PREFIXES.stream().anyMatch(threadName::startsWith), "unexpected thread " + threadName);
    }

    @Requires(property = "spec.name", value = "BlockingAnnotatedAuthenticationProviderTest")
    @Singleton
    static class AnnotatedProvider<B> implements HttpRequestAuthenticationProvider<B> {
        private final AtomicReference<String> thread = new AtomicReference<>();

        @Override
        public int getOrder() {
            return -42;
        }

        @Blocking
        @Override
        public AuthenticationResponse authenticate(@Nullable HttpRequest<B> requestContext,
                                                   AuthenticationRequest<String, String> authenticationRequest) {
            thread.set(Thread.currentThread().getName());
            if ("lebowski".equals(authenticationRequest.getIdentity())
                && "test-fixture-not-a-secret".equals(authenticationRequest.getSecret())) {
                return AuthenticationResponse.success("lebowski");
            }
            return AuthenticationResponse.failure("Over the line.");
        }
    }

    @Requires(property = "spec.name", value = "BlockingAnnotatedAuthenticationProviderTest")
    @Singleton
    @Blocking
    static class TypeAnnotatedProvider<B> implements HttpRequestAuthenticationProvider<B> {
        private final AtomicReference<String> thread = new AtomicReference<>();

        @Override
        public AuthenticationResponse authenticate(@Nullable HttpRequest<B> requestContext,
                                                   AuthenticationRequest<String, String> authenticationRequest) {
            thread.set(Thread.currentThread().getName());
            return AuthenticationResponse.failure();
        }
    }

    @Requires(property = "spec.name", value = "BlockingAnnotatedAuthenticationProviderTest")
    @Singleton
    static class NullNameProvider<B> implements HttpRequestExecutorAuthenticationProvider<B> {
        private final AtomicReference<String> thread = new AtomicReference<>();

        @Override
        public String getExecutorName() {
            return null;
        }

        @Override
        public AuthenticationResponse authenticate(@Nullable HttpRequest<B> requestContext,
                                                   AuthenticationRequest<String, String> authenticationRequest) {
            thread.set(Thread.currentThread().getName());
            return AuthenticationResponse.failure();
        }
    }

    @Requires(property = "spec.name", value = "BlockingAnnotatedAuthenticationProviderTest")
    @Singleton
    static class EmptyNameProvider<B> implements HttpRequestExecutorAuthenticationProvider<B> {
        private final AtomicReference<String> thread = new AtomicReference<>();

        @Override
        public String getExecutorName() {
            return "";
        }

        @Override
        public AuthenticationResponse authenticate(@Nullable HttpRequest<B> requestContext,
                                                   AuthenticationRequest<String, String> authenticationRequest) {
            thread.set(Thread.currentThread().getName());
            return AuthenticationResponse.failure();
        }
    }
}
