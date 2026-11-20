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
package io.micronaut.security.authentication;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Blocking;
import io.micronaut.security.authentication.provider.AuthenticationProvider;
import io.micronaut.security.authentication.provider.ExecutorAuthenticationProvider;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins the threading contract documented in {@link AuthenticationProvider}.
 */
class AuthenticationProviderSchedulingTest {

    private static final String BLOCKING_ANNOTATED = "AuthenticationProviderSchedulingTest.blockingAnnotated";
    private static final String EXECUTOR = "AuthenticationProviderSchedulingTest.executor";

    @Test
    void blockingAnnotationDoesNotOffloadAnAuthenticationProvider() {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of("spec.name", BLOCKING_ANNOTATED))) {
            AuthenticationResponse response = authenticate(ctx);

            assertTrue(response.isAuthenticated());
            assertEquals(Thread.currentThread().getName(), ctx.getBean(BlockingAnnotatedAuthenticationProvider.class).threadName);
        }
    }

    @Test
    void executorAuthenticationProviderIsOffloadedToItsExecutor() {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of("spec.name", EXECUTOR))) {
            AuthenticationResponse response = authenticate(ctx);

            assertTrue(response.isAuthenticated());
            String threadName = ctx.getBean(OffloadedAuthenticationProvider.class).threadName;
            assertNotNull(threadName);
            assertNotEquals(Thread.currentThread().getName(), threadName);
        }
    }

    @SuppressWarnings("unchecked")
    private static AuthenticationResponse authenticate(ApplicationContext ctx) {
        Authenticator<Object> authenticator = ctx.getBean(Authenticator.class);
        return Mono.from(authenticator.authenticate(null, new UsernamePasswordCredentials("sherlock", "password"))).block();
    }

    @Requires(property = "spec.name", value = BLOCKING_ANNOTATED)
    @Singleton
    static class BlockingAnnotatedAuthenticationProvider<T, I, S> implements AuthenticationProvider<T, I, S> {
        volatile String threadName;

        @Blocking
        @Override
        public AuthenticationResponse authenticate(@Nullable T requestContext, AuthenticationRequest<I, S> authRequest) {
            threadName = Thread.currentThread().getName();
            return AuthenticationResponse.success("sherlock");
        }
    }

    @Requires(property = "spec.name", value = EXECUTOR)
    @Singleton
    static class OffloadedAuthenticationProvider<T, I, S> implements ExecutorAuthenticationProvider<T, I, S> {
        volatile String threadName;

        @Override
        public AuthenticationResponse authenticate(@Nullable T requestContext, AuthenticationRequest<I, S> authRequest) {
            threadName = Thread.currentThread().getName();
            return AuthenticationResponse.success("sherlock");
        }
    }
}
