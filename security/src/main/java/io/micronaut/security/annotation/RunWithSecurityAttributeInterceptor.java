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
package io.micronaut.security.annotation;

import io.micronaut.aop.InterceptorBean;
import io.micronaut.aop.InterceptedMethod;
import io.micronaut.aop.MethodInterceptor;
import io.micronaut.aop.MethodInvocationContext;
import io.micronaut.core.annotation.AnnotationMetadata;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.convert.ConversionService;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.context.SecurityContext;
import io.micronaut.security.context.SecurityContextHolder;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletionStage;

/**
 * Intercepts {@link RunWithSecurityAttribute} methods and scopes a temporary authentication attribute.
 *
 * @since 5.1.0
 */
@Internal
@Singleton
@InterceptorBean(RunWithSecurityAttribute.class)
public final class RunWithSecurityAttributeInterceptor implements MethodInterceptor<Object, Object> {

    @Override
    public Object intercept(MethodInvocationContext<Object, Object> context) {
        String name = context.stringValue(RunWithSecurityAttribute.class, "name").orElse(null);
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("@RunWithSecurityAttribute name cannot be blank");
        }

        SecurityContext securityContext = SecurityContextHolder.getSecurityContext();
        Authentication authentication = securityContext.getAuthentication();
        if (authentication == null) {
            return context.proceed();
        }

        String value = context.stringValue(RunWithSecurityAttribute.class, AnnotationMetadata.VALUE_MEMBER)
            .orElse("true");
        Authentication scopedAuthentication = new RunWithSecurityAttributeAuthentication(authentication, name, value);
        securityContext.withAuthentication(scopedAuthentication);

        boolean restoreOnExit = true;
        try {
            Object result = context.proceed();
            if (result instanceof CompletionStage<?> completionStage) {
                restoreOnExit = false;
                return completionStage.whenComplete((unused, throwable) -> restore(securityContext, authentication));
            }
            if (result instanceof Publisher<?> publisher) {
                return wrapPublisher(context, publisher, securityContext, name, value);
            }
            return result;
        } finally {
            if (restoreOnExit) {
                restore(securityContext, authentication);
            }
        }
    }

    @NonNull
    private Object wrapPublisher(@NonNull MethodInvocationContext<Object, Object> context,
                                 @NonNull Publisher<?> publisher,
                                 @NonNull SecurityContext securityContext,
                                 @NonNull String name,
                                 @NonNull String value) {
        if (publisher instanceof Mono<?> mono) {
            return wrapMono(mono, securityContext, name, value);
        }
        if (publisher instanceof Flux<?> flux) {
            return wrapFlux(flux, securityContext, name, value);
        }
        Publisher<?> scopedPublisher = wrapFlux(publisher, securityContext, name, value);
        Object result = InterceptedMethod.of(context, ConversionService.SHARED).handleResult(scopedPublisher);
        Class<?> returnType = context.getReturnType().getType();
        if (!returnType.isInstance(result)) {
            throw new IllegalStateException("@RunWithSecurityAttribute does not support concrete Publisher return type: "
                + returnType.getName());
        }
        return result;
    }

    @NonNull
    private <T> Mono<T> wrapMono(@NonNull Mono<T> mono,
                                 @NonNull SecurityContext securityContext,
                                 @NonNull String name,
                                 @NonNull String value) {
        return Mono.defer(() -> {
            Authentication previousAuthentication = securityContext.getAuthentication();
            if (previousAuthentication == null) {
                return mono;
            }
            securityContext.withAuthentication(new RunWithSecurityAttributeAuthentication(previousAuthentication, name, value));
            return mono.doFinally(signalType -> restore(securityContext, previousAuthentication));
        });
    }

    @NonNull
    private <T> Flux<T> wrapFlux(@NonNull Publisher<T> publisher,
                                 @NonNull SecurityContext securityContext,
                                 @NonNull String name,
                                 @NonNull String value) {
        return Flux.defer(() -> {
            Authentication previousAuthentication = securityContext.getAuthentication();
            if (previousAuthentication == null) {
                return Flux.from(publisher);
            }
            securityContext.withAuthentication(new RunWithSecurityAttributeAuthentication(previousAuthentication, name, value));
            return Flux.from(publisher).doFinally(signalType -> restore(securityContext, previousAuthentication));
        });
    }

    private void restore(@NonNull SecurityContext securityContext, @NonNull Authentication authentication) {
        securityContext.withAuthentication(authentication);
    }

    private static final class RunWithSecurityAttributeAuthentication implements Authentication {
        private static final long serialVersionUID = 1L;

        private final Authentication delegate;
        private final Map<String, Object> attributes;

        private RunWithSecurityAttributeAuthentication(Authentication delegate, String name, String value) {
            this.delegate = delegate;
            Map<String, Object> mutableAttributes = new LinkedHashMap<>(delegate.getAttributes());
            mutableAttributes.put(name, value);
            this.attributes = Collections.unmodifiableMap(mutableAttributes);
        }

        @Override
        public String getName() {
            return delegate.getName();
        }

        @Override
        @NonNull
        public Collection<String> getRoles() {
            return delegate.getRoles();
        }

        @Override
        @NonNull
        public Map<String, Object> getAttributes() {
            return attributes;
        }
    }
}
