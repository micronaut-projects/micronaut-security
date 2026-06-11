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
import io.micronaut.core.convert.ConversionService;
import io.micronaut.security.annotation.RunAsAuthentication;
import io.micronaut.security.context.SecurityContext;
import io.micronaut.security.context.ServerRequestContextSecurityContextSupplier;
import org.jspecify.annotations.Nullable;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

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
        try (RunAsSecurityContext _ = new RunAsSecurityContext(runAsAuthentication)) {
            return context.proceed();
        }
    }

    private Publisher<?> interceptPublisher(InterceptedMethod interceptedMethod,
                                            Authentication runAsAuthentication) {
        Publisher<?> publisher;
        try (RunAsSecurityContext _ = new RunAsSecurityContext(runAsAuthentication)) {
            publisher = interceptedMethod.interceptResultAsPublisher();
        }
        return Flux.using(
            () -> new RunAsSecurityContext(runAsAuthentication),
            _ -> Flux.from(publisher),
            RunAsSecurityContext::close
        );
    }

    private CompletionStage<?> interceptCompletionStage(InterceptedMethod interceptedMethod,
                                                       Authentication runAsAuthentication) {
        RunAsSecurityContext runAsSecurityContext = new RunAsSecurityContext(runAsAuthentication);
        CompletionStage<?> completionStage;
        try {
            completionStage = interceptedMethod.interceptResultAsCompletionStage();
        } catch (RuntimeException | Error e) {
            runAsSecurityContext.close();
            throw e;
        }

        CompletableFuture<Object> result = new CompletableFuture<>();
        completionStage.whenComplete((value, throwable) -> {
            runAsSecurityContext.close();
            if (throwable == null) {
                result.complete(value);
            } else {
                result.completeExceptionally(throwable);
            }
        });
        return result;
    }

    private static final class RunAsSecurityContext implements AutoCloseable {
        private final ServerRequestContextSecurityContextSupplier.ScopedSecurityContext scopedContext;
        private final SecurityContext securityContext;
        private final @Nullable Authentication previousAuthentication;
        private final @Nullable String previousToken;
        private final @Nullable Integer previousRejectionStatus;

        private RunAsSecurityContext(Authentication runAsAuthentication) {
            scopedContext = ServerRequestContextSecurityContextSupplier.openSecurityContext();
            securityContext = scopedContext.getSecurityContext();
            previousAuthentication = securityContext.getAuthentication();
            previousToken = securityContext.getToken();
            previousRejectionStatus = securityContext.getRejectionStatus();
            securityContext.withAuthentication(runAsAuthentication);
        }

        @Override
        public void close() {
            securityContext.withAuthentication(previousAuthentication)
                .withToken(previousToken)
                .withRejectionStatus(previousRejectionStatus);
            scopedContext.close();
        }
    }
}
