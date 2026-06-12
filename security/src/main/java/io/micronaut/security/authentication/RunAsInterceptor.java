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

import io.micronaut.aop.InterceptorBean;
import io.micronaut.aop.InterceptedMethod;
import io.micronaut.aop.MethodInterceptor;
import io.micronaut.aop.MethodInvocationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.async.propagation.ReactivePropagation;
import io.micronaut.core.convert.ConversionService;
import io.micronaut.core.propagation.PropagatedContext;
import io.micronaut.security.annotation.RunAsAuthentication;
import io.micronaut.security.context.SecurityContext;
import io.micronaut.security.context.SecurityContextHolder;
import io.micronaut.security.context.ServerRequestContextSecurityContextSupplier;
import org.jspecify.annotations.Nullable;
import org.reactivestreams.Publisher;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Supplier;

/**
 * Intercepts {@link RunAsAuthentication} and temporarily replaces the current security context
 * authentication for the intercepted invocation.
 */
@Requires(beans = AuthenticationMapper.class)
@Internal
@InterceptorBean(RunAsAuthentication.class)
final class RunAsInterceptor implements MethodInterceptor<Object, Object> {
    private final AuthenticationMapper authenticationMapper;

    RunAsInterceptor(AuthenticationMapper authenticationMapper) {
        this.authenticationMapper = authenticationMapper;
    }

    @Override
    @Nullable
    public Object intercept(MethodInvocationContext<Object, Object> context) {
        String value = context.stringValue(RunAsAuthentication.class).orElse(null);
        if (value == null || value.isBlank()) {
            return context.proceed();
        }

        Authentication runAsAuthentication;
        try {
            runAsAuthentication = authenticationMapper.read(value);
        } catch (IOException e) {
            throw new ConfigurationException("Invalid @RunAsAuthentication value", e);
        }
        return intercept(context, runAsAuthentication);
    }

    public Object intercept(MethodInvocationContext<Object, Object> context, Authentication runAsAuthentication) {
        InterceptedMethod interceptedMethod = InterceptedMethod.of(context, ConversionService.SHARED);
        try {
            return switch (interceptedMethod.resultType()) {
                case PUBLISHER -> interceptedMethod.handleResult(
                    interceptPublisher(interceptedMethod, runAsAuthentication)
                );
                case COMPLETION_STAGE -> interceptedMethod.handleResult(
                    interceptCompletionStage(interceptedMethod, runAsAuthentication)
                );
                case SYNCHRONOUS -> interceptSynchronous(context, runAsAuthentication);
            };
        } catch (Exception e) {
            return interceptedMethod.handleException(e);
        }
    }

    @Nullable
    private Object interceptSynchronous(MethodInvocationContext<Object, Object> context,
                                        Authentication runAsAuthentication) {
        PropagatedContext propagatedContext = withRunAsAuthentication(runAsAuthentication);
        return ServerRequestContextSecurityContextSupplier.withSecurityContext(
            propagatedContext,
            context::proceed
        );
    }

    private Publisher<?> interceptPublisher(InterceptedMethod interceptedMethod,
                                            Authentication runAsAuthentication) {
        PropagatedContext propagatedContext = withRunAsAuthentication(runAsAuthentication);
        Publisher<?> publisher = ServerRequestContextSecurityContextSupplier.withSecurityContext(
            propagatedContext,
            (Supplier<Publisher<?>>) interceptedMethod::interceptResultAsPublisher
        );
        return ReactivePropagation.propagate(propagatedContext, publisher);
    }

    private CompletionStage<?> interceptCompletionStage(InterceptedMethod interceptedMethod,
                                                       Authentication runAsAuthentication) {
        PropagatedContext propagatedContext = withRunAsAuthentication(runAsAuthentication);
        SecurityContextState state = replaceCurrentAuthentication(runAsAuthentication);
        boolean restoreOnExit = true;
        try {
            CompletionStage<?> completionStage = ServerRequestContextSecurityContextSupplier.withSecurityContext(
                propagatedContext,
                interceptedMethod::interceptResultAsCompletionStage
            );
            CompletableFuture<Object> result = new CompletableFuture<>();
            completionStage.whenComplete((value, throwable) -> {
                state.restore();
                if (throwable == null) {
                    result.complete(value);
                } else {
                    result.completeExceptionally(throwable);
                }
            });
            restoreOnExit = false;
            return result;
        } finally {
            if (restoreOnExit) {
                state.restore();
            }
        }
    }

    private static SecurityContextState replaceCurrentAuthentication(Authentication authentication) {
        SecurityContext securityContext = SecurityContextHolder.getSecurityContext();
        SecurityContextState state = new SecurityContextState(
            securityContext,
            securityContext.getAuthentication(),
            securityContext.getToken(),
            securityContext.getRejectionStatus()
        );
        securityContext.withAuthentication(authentication);
        return state;
    }

    private static PropagatedContext withRunAsAuthentication(Authentication runAsAuthentication) {
        return ServerRequestContextSecurityContextSupplier.withAuthentication(runAsAuthentication);
    }

    private record SecurityContextState(
        SecurityContext securityContext,
        @Nullable Authentication authentication,
        @Nullable String token,
        @Nullable Integer rejectionStatus
    ) {

        void restore() {
            securityContext.withAuthentication(authentication)
                .withToken(token)
                .withRejectionStatus(rejectionStatus);
        }
    }
}
