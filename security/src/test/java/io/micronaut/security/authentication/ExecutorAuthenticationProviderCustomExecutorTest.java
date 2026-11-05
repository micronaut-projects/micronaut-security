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
import io.micronaut.security.authentication.provider.HttpRequestExecutorAuthenticationProvider;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * An {@link io.micronaut.security.authentication.provider.ExecutorAuthenticationProvider} that names an executor
 * other than {@code blocking} or {@code io} must still run on that executor, never on the thread that subscribes
 * to the {@link Authenticator} (the Netty event loop in a running server).
 */
@Property(name = "spec.name", value = "ExecutorAuthenticationProviderCustomExecutorTest")
@Property(name = "micronaut.executors.custom-auth.type", value = "fixed")
@Property(name = "micronaut.executors.custom-auth.n-threads", value = "2")
@MicronautTest(startApplication = false)
class ExecutorAuthenticationProviderCustomExecutorTest {

    private static final String CUSTOM_EXECUTOR_NAME = "custom-auth";

    @Test
    void acceptedCredentialsAreCheckedOnTheCustomExecutor(Authenticator<HttpRequest<?>> authenticator,
                                                          CustomExecutorAuthenticationProvider<?> provider) {
        provider.executedThreadName.set(null);

        AuthenticationResponse response = Mono.from(authenticator.authenticate(HttpRequest.GET("/"),
            new UsernamePasswordCredentials("lebowski", "test-fixture-not-a-secret"))).block();

        assertNotNull(response);
        assertTrue(response.isAuthenticated());
        assertEquals("lebowski", response.getAuthentication().map(Authentication::getName).orElse(null));
        assertExecutedOnCustomExecutor(provider);
    }

    @Test
    void rejectedCredentialsAreCheckedOnTheCustomExecutor(Authenticator<HttpRequest<?>> authenticator,
                                                          CustomExecutorAuthenticationProvider<?> provider) {
        provider.executedThreadName.set(null);

        AuthenticationResponse response = Mono.from(authenticator.authenticate(HttpRequest.GET("/"),
            new UsernamePasswordCredentials("smoky", "wrong-test-fixture-not-a-secret"))).block();

        assertNotNull(response);
        assertFalse(response.isAuthenticated());
        assertExecutedOnCustomExecutor(provider);
    }

    private static void assertExecutedOnCustomExecutor(CustomExecutorAuthenticationProvider<?> provider) {
        String executedThreadName = provider.executedThreadName.get();
        assertNotNull(executedThreadName, "provider was not invoked");
        assertNotEquals(Thread.currentThread().getName(), executedThreadName,
            "provider ran on the subscribing thread instead of the executor it names");
        assertTrue(executedThreadName.startsWith(CUSTOM_EXECUTOR_NAME + "-executor"),
            "provider ran on thread " + executedThreadName + " instead of the " + CUSTOM_EXECUTOR_NAME + " executor");
    }

    @Requires(property = "spec.name", value = "ExecutorAuthenticationProviderCustomExecutorTest")
    @Singleton
    static class CustomExecutorAuthenticationProvider<B> implements HttpRequestExecutorAuthenticationProvider<B> {
        private final AtomicReference<String> executedThreadName = new AtomicReference<>();

        @Override
        public String getExecutorName() {
            return CUSTOM_EXECUTOR_NAME;
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
