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
import io.micronaut.aop.MethodInterceptor;
import io.micronaut.aop.MethodInvocationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.context.SecurityContext;
import io.micronaut.security.context.ServerRequestContextSecurityContextSupplier;
import jakarta.annotation.security.RunAs;
import org.jspecify.annotations.Nullable;

import java.io.IOException;

/**
 * Intercepts {@link RunAs} and temporarily replaces the current security context
 * authentication for the intercepted invocation.
 */
@Requires(beans = AuthenticationMapper.class)
@Internal
@InterceptorBean(RunAs.class)
final class RunAsInterceptor implements MethodInterceptor<Object, Object> {
    private final AuthenticationMapper authenticationMapper;

    RunAsInterceptor(AuthenticationMapper authenticationMapper) {
        this.authenticationMapper = authenticationMapper;
    }

    @Override
    @Nullable
    public Object intercept(MethodInvocationContext<Object, Object> context) {
        String value = context.stringValue(RunAs.class).orElse(null);
        if (value == null || value.isBlank()) {
            return context.proceed();
        }

        Authentication runAsAuthentication;
        try {
            runAsAuthentication = authenticationMapper.read(value);
        } catch (IOException e) {
            throw new ConfigurationException("Invalid @RunAs authentication value", e);
        }

        ServerRequestContextSecurityContextSupplier.ScopedSecurityContext scopedContext = ServerRequestContextSecurityContextSupplier.openSecurityContext();
        SecurityContext securityContext = scopedContext.getSecurityContext();
        Authentication previousAuthentication = securityContext.getAuthentication();
        String previousToken = securityContext.getToken();
        Integer previousRejectionStatus = securityContext.getRejectionStatus();
        try {
            securityContext.withAuthentication(runAsAuthentication);
            return context.proceed();
        } finally {
            securityContext.withAuthentication(previousAuthentication)
                .withToken(previousToken)
                .withRejectionStatus(previousRejectionStatus);
            scopedContext.close();
        }
    }
}
