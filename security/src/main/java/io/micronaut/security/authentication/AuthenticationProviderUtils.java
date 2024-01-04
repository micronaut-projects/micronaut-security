/*
 * Copyright 2017-2023 original authors
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

import io.micronaut.context.BeanContext;
import io.micronaut.context.BeanRegistration;
import io.micronaut.core.annotation.Blocking;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpRequest;
import io.micronaut.inject.ExecutableMethod;
import io.micronaut.security.authentication.provider.AuthenticationProvider;

import java.lang.annotation.Annotation;

/**
 * Utility class to check whether {@link io.micronaut.security.authentication.provider.AuthenticationProvider#authenticate(Object, AuthenticationRequest)} is annotated with {@link Blocking}.
 */
@Internal
final class AuthenticationProviderUtils {
    private static final String METHOD_AUTHENTICATE = "authenticate";

    private AuthenticationProviderUtils() {
    }

    public static <B, I, S> boolean isAuthenticateBlocking(BeanContext beanContext,
                                                 @NonNull AuthenticationProvider<B, I, S> authenticationProvider) {
        if (isMethodBlocking(beanContext, authenticationProvider, METHOD_AUTHENTICATE, Object.class, AuthenticationRequest.class)) {
            return true;
        }
        return isMethodBlocking(beanContext, authenticationProvider, METHOD_AUTHENTICATE, HttpRequest.class, AuthenticationRequest.class);
    }

    private static boolean isMethodBlocking(BeanContext beanContext,
                                           @NonNull Object bean,
                                           String methodName,
                                           Class<?>... argumentTypes) {
        return beanContext.findBeanRegistration(bean)
                .map(BeanRegistration::getBeanDefinition)
                .map(beanDefinition -> beanDefinition
                .findMethod(methodName, argumentTypes)
                .filter(AuthenticationProviderUtils::isBlockingMethod)
                .isPresent())
                .orElse(false);
    }

    private static boolean isBlockingMethod(ExecutableMethod<?, ?> executableMethod) {
        return isMethodAnnotatedWith(executableMethod, Blocking.class);
    }

    private static boolean isMethodAnnotatedWith(ExecutableMethod<?, ?> executableMethod, Class<? extends Annotation> annotationClass) {
        return executableMethod.getAnnotationMetadata().hasAnnotation(annotationClass);
    }
}
