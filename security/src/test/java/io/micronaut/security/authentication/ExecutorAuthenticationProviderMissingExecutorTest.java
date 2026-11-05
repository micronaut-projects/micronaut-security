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
import io.micronaut.http.HttpRequest;
import io.micronaut.scheduling.TaskExecutors;
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
 * An {@link io.micronaut.security.authentication.provider.ExecutorAuthenticationProvider} that names an executor
 * which is not registered in the bean context falls back to the {@code blocking} executor instead of running on
 * the thread that subscribes to the {@link Authenticator}.
 */
@Property(name = "spec.name", value = "ExecutorAuthenticationProviderMissingExecutorTest")
@MicronautTest(startApplication = false)
class ExecutorAuthenticationProviderMissingExecutorTest {

    /**
     * {@link TaskExecutors#BLOCKING} is backed by either the {@link TaskExecutors#VIRTUAL} or the
     * {@link TaskExecutors#IO} executor depending on the JDK and configuration; their threads are named after them.
     */
    private static final List<String> BLOCKING_EXECUTOR_THREAD_PREFIXES =
        List.of(TaskExecutors.VIRTUAL + "-executor", TaskExecutors.IO + "-executor");

    @Test
    void acceptedCredentialsAreCheckedOnTheBlockingExecutor(Authenticator<HttpRequest<?>> authenticator,
                                                            MissingExecutorAuthenticationProvider<?> provider) {
        provider.executedThreadName.set(null);

        AuthenticationResponse response = Mono.from(authenticator.authenticate(HttpRequest.GET("/"),
            new UsernamePasswordCredentials("lebowski", "test-fixture-not-a-secret"))).block();

        assertNotNull(response);
        assertTrue(response.isAuthenticated());
        assertEquals("lebowski", response.getAuthentication().map(Authentication::getName).orElse(null));
        assertExecutedOnBlockingExecutor(provider);
    }

    @Test
    void rejectedCredentialsAreCheckedOnTheBlockingExecutor(Authenticator<HttpRequest<?>> authenticator,
                                                            MissingExecutorAuthenticationProvider<?> provider) {
        provider.executedThreadName.set(null);

        AuthenticationResponse response = Mono.from(authenticator.authenticate(HttpRequest.GET("/"),
            new UsernamePasswordCredentials("smoky", "wrong-test-fixture-not-a-secret"))).block();

        assertNotNull(response);
        assertFalse(response.isAuthenticated());
        assertExecutedOnBlockingExecutor(provider);
    }

    private static void assertExecutedOnBlockingExecutor(MissingExecutorAuthenticationProvider<?> provider) {
        String executedThreadName = provider.executedThreadName.get();
        assertNotNull(executedThreadName, "provider was not invoked");
        assertNotEquals(Thread.currentThread().getName(), executedThreadName,
            "provider ran on the subscribing thread instead of the blocking executor");
        assertTrue(BLOCKING_EXECUTOR_THREAD_PREFIXES.stream().anyMatch(executedThreadName::startsWith),
            "provider ran on thread " + executedThreadName + " instead of the blocking executor");
    }

    @Requires(property = "spec.name", value = "ExecutorAuthenticationProviderMissingExecutorTest")
    @Singleton
    static class MissingExecutorAuthenticationProvider<B> implements HttpRequestExecutorAuthenticationProvider<B> {
        private final AtomicReference<String> executedThreadName = new AtomicReference<>();

        @Override
        public String getExecutorName() {
            return "executor-that-does-not-exist";
        }

        @Override
        public AuthenticationResponse authenticate(@Nullable HttpRequest<B> requestContext,
                                                   AuthenticationRequest<String, String> authenticationRequest) {
            executedThreadName.set(Thread.currentThread().getName());
            if ("lebowski".equals(authenticationRequest.getIdentity())
                && "test-fixture-not-a-secret".equals(authenticationRequest.getSecret())) {
                return AuthenticationResponse.success("lebowski");
            }
            return AuthenticationResponse.failure("Over the line.");
        }
    }
}
