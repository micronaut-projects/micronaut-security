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
import io.micronaut.context.BeanContext;
import io.micronaut.context.Qualifier;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.BeanInstantiationException;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.security.authentication.provider.AuthenticationProvider;
import io.micronaut.security.authentication.provider.ExecutorAuthenticationProvider;
import io.micronaut.security.config.SecurityConfigurationProperties;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link Authenticator} builds its provider chain (reactive providers plus imperative providers adapted to reactive,
 * sorted by order, each {@link ExecutorAuthenticationProvider} bound to its executor) once, at construction time,
 * rather than on every authentication. A provider naming an executor that does not exist as a bean is a
 * configuration error reported when the Authenticator is created, not silently run inline on the caller thread.
 */
class AuthenticatorProviderChainTest {

    private static final String SPEC_NAME = "AuthenticatorProviderChainTest";
    private static final String MISSING_EXECUTOR = "does-not-exist";
    private static final UsernamePasswordCredentials CREDENTIALS = new UsernamePasswordCredentials("sherlock", "password");

    @Test
    void providerNamingAMissingExecutorFailsAuthenticatorConstruction() {
        ExecutorAuthenticationProvider<Object, Object, Object> provider = provider(MISSING_EXECUTOR, () -> AuthenticationResponse.success("sherlock"));
        try (ApplicationContext ctx = ApplicationContext.run()) {
            ConfigurationException e = assertThrows(ConfigurationException.class, () -> authenticator(ctx, List.of(provider)));

            assertTrue(e.getMessage().contains(MISSING_EXECUTOR));
            assertTrue(e.getMessage().contains(provider.getClass().getName()));
            assertTrue(e.getMessage().contains(ExecutorService.class.getName()));
        }
    }

    @Test
    void providerBeanNamingAMissingExecutorFailsAuthenticatorBeanCreation() {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of("spec.name", SPEC_NAME))) {
            BeanInstantiationException e = assertThrows(BeanInstantiationException.class, () -> ctx.getBean(Authenticator.class));

            ConfigurationException cause = configurationException(e);
            assertNotNull(cause);
            assertTrue(cause.getMessage().contains(MISSING_EXECUTOR));
            assertTrue(cause.getMessage().contains(MissingExecutorAuthenticationProvider.class.getName()));
        }
    }

    @Test
    void executorBeanIsResolvedOncePerNameAtConstruction() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            BeanContext beanContext = beanContextWith(executor);
            List<AuthenticationProvider<Object, ?, ?>> providers = List.of(
                    provider(TaskExecutors.BLOCKING, AuthenticationResponse::failure),
                    provider(TaskExecutors.BLOCKING, AuthenticationResponse::failure));

            Authenticator<Object> authenticator = authenticator(beanContext, providers);

            // both providers share the executor name, so the bean is looked up once, before any authentication
            verify(beanContext, times(1)).findBean(eq(ExecutorService.class), any());

            assertFalse(authenticate(authenticator).isAuthenticated());
            assertFalse(authenticate(authenticator).isAuthenticated());

            // authenticating does not look the executor bean up again
            verify(beanContext, times(1)).findBean(eq(ExecutorService.class), any());
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void providerRunsOnTheExecutorBeanItNames() {
        String threadName = "authenticator-provider-chain-test";
        ExecutorService executor = Executors.newSingleThreadExecutor(r -> new Thread(r, threadName));
        try {
            // only the blocking and io executor names route an imperative provider through the reactive path (see
            // Authenticator#isImperativeAuthenticationProviderIsBlocking); any other name runs the provider inline
            Authenticator<Object> authenticator = authenticator(beanContextWith(executor),
                    List.of(provider(TaskExecutors.IO, () -> AuthenticationResponse.success(Thread.currentThread().getName()))));

            AuthenticationResponse rsp = authenticate(authenticator);

            assertTrue(rsp.isAuthenticated());
            assertEquals(threadName, rsp.getAuthentication().orElseThrow().getName());
        } finally {
            executor.shutdownNow();
        }
    }

    private static Authenticator<Object> authenticator(BeanContext beanContext, List<AuthenticationProvider<Object, ?, ?>> providers) {
        return new Authenticator<>(beanContext, List.of(), providers, new SecurityConfigurationProperties());
    }

    private static AuthenticationResponse authenticate(Authenticator<Object> authenticator) {
        return Mono.from(authenticator.authenticate(new Object(), CREDENTIALS)).block();
    }

    @SuppressWarnings("unchecked")
    private static BeanContext beanContextWith(ExecutorService executor) {
        BeanContext beanContext = mock(BeanContext.class);
        when(beanContext.findBean(eq(ExecutorService.class), any(Qualifier.class))).thenReturn(Optional.of(executor));
        return beanContext;
    }

    private static ExecutorAuthenticationProvider<Object, Object, Object> provider(String executorName, Supplier<AuthenticationResponse> response) {
        return new ExecutorAuthenticationProvider<>() {
            @Override
            public String getExecutorName() {
                return executorName;
            }

            @Override
            public AuthenticationResponse authenticate(Object requestContext, AuthenticationRequest<Object, Object> authenticationRequest) {
                return response.get();
            }
        };
    }

    private static ConfigurationException configurationException(Throwable t) {
        for (Throwable current = t; current != null; current = current.getCause()) {
            if (current instanceof ConfigurationException e) {
                return e;
            }
        }
        return null;
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class MissingExecutorAuthenticationProvider<T> implements ExecutorAuthenticationProvider<T, String, String> {

        @Override
        public String getExecutorName() {
            return MISSING_EXECUTOR;
        }

        @Override
        public AuthenticationResponse authenticate(T requestContext, AuthenticationRequest<String, String> authenticationRequest) {
            return AuthenticationResponse.success("sherlock");
        }
    }
}
