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
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.AnnotationValue;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.async.propagation.ReactivePropagation;
import io.micronaut.core.convert.ConversionService;
import io.micronaut.core.propagation.PropagatedContext;
import io.micronaut.security.annotation.RunAs;
import io.micronaut.security.context.SecurityContext;
import io.micronaut.security.context.SecurityContextHolder;
import io.micronaut.security.context.ServerRequestContextSecurityContextSupplier;
import org.jspecify.annotations.Nullable;
import org.reactivestreams.Publisher;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Supplier;

/**
 * Intercepts {@link RunAs} and temporarily replaces the current security context
 * authentication for the intercepted invocation.
 */
@Internal
@InterceptorBean(RunAs.class)
final class RunAsInterceptor implements MethodInterceptor<Object, Object> {
    private static final String MEMBER_ATTRIBUTES = "attributes";
    private static final String MEMBER_APPEND_ATTRIBUTES = "appendAttributes";
    private static final String MEMBER_APPEND_ROLES = "appendRoles";
    private static final String MEMBER_KEY = "key";
    private static final String MEMBER_NAME = "name";
    private static final String MEMBER_ROLES = "roles";
    private static final String MEMBER_VALUE = "value";

    @Override
    @Nullable
    public Object intercept(MethodInvocationContext<Object, Object> context) {
        return intercept(context, authentication(context));
    }

    private static Object intercept(MethodInvocationContext<Object, Object> context, Authentication runAs) {
        InterceptedMethod interceptedMethod = InterceptedMethod.of(context, ConversionService.SHARED);
        try {
            return switch (interceptedMethod.resultType()) {
                case PUBLISHER -> interceptedMethod.handleResult(
                    interceptPublisher(interceptedMethod, runAs)
                );
                case COMPLETION_STAGE -> interceptedMethod.handleResult(
                    interceptCompletionStage(interceptedMethod, runAs)
                );
                case SYNCHRONOUS -> interceptSynchronous(context, runAs);
            };
        } catch (Exception e) {
            return interceptedMethod.handleException(e);
        }
    }

    private static Authentication authentication(MethodInvocationContext<Object, Object> context) {
        Authentication previousAuthentication = SecurityContextHolder.getSecurityContext().getAuthentication();
        String name = context.stringValue(RunAs.class, MEMBER_NAME).orElse("");
        if (name.isBlank() && previousAuthentication == null) {
            throw new ConfigurationException("@RunAs name cannot be blank");
        }
        String[] roles = context.stringValues(RunAs.class, MEMBER_ROLES);
        for (String role : roles) {
            if (role.isBlank()) {
                throw new ConfigurationException("@RunAs roles cannot contain blank values");
            }
        }
        List<String> roleList = List.of(roles);
        Map<String, Object> attributes = new LinkedHashMap<>();
        boolean appendAttributes = context.booleanValue(RunAs.class, MEMBER_APPEND_ATTRIBUTES).orElse(true);
        boolean appendRoles = context.booleanValue(RunAs.class, MEMBER_APPEND_ROLES).orElse(true);
        context.findAnnotation(RunAs.class).ifPresent(annotation -> {
            for (AnnotationValue<?> attribute : annotation.getAnnotations(MEMBER_ATTRIBUTES)) {
                String key = attribute.stringValue(MEMBER_KEY).orElse("");
                String value = attribute.stringValue(MEMBER_VALUE).orElse("");
                if (key.isBlank()) {
                    throw new ConfigurationException("@RunAs attribute keys cannot be blank");
                }
                attributes.put(key, value);
            }
        });
        Authentication runAs = previousAuthentication == null ? Authentication.build(name) : previousAuthentication;
        if (!name.isBlank()) {
            runAs = runAs.withUsername(name);
        }
        runAs = runAs.withRoles(roleList, appendRoles);
        return runAs.withAttributes(attributes, appendAttributes);
    }

    @Nullable
    private static Object interceptSynchronous(MethodInvocationContext<Object, Object> context,
                                               Authentication runAs) {
        PropagatedContext propagatedContext = withRunAs(runAs);
        return ServerRequestContextSecurityContextSupplier.withSecurityContext(
            propagatedContext,
            context::proceed
        );
    }

    private static Publisher<?> interceptPublisher(InterceptedMethod interceptedMethod,
                                                   Authentication runAs) {
        PropagatedContext propagatedContext = withRunAs(runAs);
        Publisher<?> publisher = ServerRequestContextSecurityContextSupplier.withSecurityContext(
            propagatedContext,
            (Supplier<Publisher<?>>) interceptedMethod::interceptResultAsPublisher
        );
        return ReactivePropagation.propagate(propagatedContext, publisher);
    }

    private static CompletionStage<?> interceptCompletionStage(InterceptedMethod interceptedMethod,
                                                              Authentication runAs) {
        PropagatedContext propagatedContext = withRunAs(runAs);
        SecurityContextState state = replaceCurrentAuthentication(runAs);
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

    private static PropagatedContext withRunAs(Authentication runAs) {
        return ServerRequestContextSecurityContextSupplier.withAuthentication(runAs);
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
