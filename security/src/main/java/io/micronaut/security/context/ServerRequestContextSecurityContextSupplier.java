/*
 * Copyright 2017-2025 original authors
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
package io.micronaut.security.context;

import io.micronaut.core.annotation.Internal;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.context.ServerRequestContext;

/**
 * Default {@link SecurityContextSupplier} implementation backed by the current
 * {@link ServerRequestContext}.
 *
 * @since 4.18.0
 */
@Internal
public final class ServerRequestContextSecurityContextSupplier implements SecurityContextSupplier {
    private static final ThreadLocal<SecurityContext> THREAD_LOCAL_SECURITY_CONTEXT = new ThreadLocal<>();

    @NonNull
    public SecurityContext get(@Nullable HttpRequest<?> request) {
        return new MutableAttributeHolderSecurityContext(request);
    }

    @NonNull
    @Override
    public SecurityContext getSecurityContext() {
        HttpRequest<?> currentRequest = currentRequest();
        if (currentRequest != null) {
            return get(currentRequest);
        }
        SecurityContext securityContext = THREAD_LOCAL_SECURITY_CONTEXT.get();
        return securityContext == null ? new MutableSecurityContext() : securityContext;
    }

    /**
     * Convenience method to get a {@link SecurityContext} without the need of invoking {@link ServerRequestContext#currentRequest()} when you already have the HTTP Request available.
     * @param httpRequest HTTP Request
     * @return The current Security Context
     */
    @NonNull
    public static SecurityContext getSecurityContext(@Nullable HttpRequest<?> httpRequest) {
        if (SecurityContextHolder.INSTANCE instanceof ServerRequestContextSecurityContextSupplier supplier) {
            return supplier.get(httpRequest);
        }
        return SecurityContextHolder.getSecurityContext();
    }

    /**
     * Opens a security context scope for code that does not run with a server request.
     *
     * @return The scoped security context
     */
    @Internal
    @NonNull
    public static ScopedSecurityContext openSecurityContext() {
        if (SecurityContextHolder.INSTANCE instanceof ServerRequestContextSecurityContextSupplier supplier) {
            return supplier.open();
        }
        return new ScopedSecurityContext(SecurityContextHolder.getSecurityContext(), false);
    }

    @Nullable
    private HttpRequest<?> currentRequest() {
        return ServerRequestContext.currentRequest().orElse(null);
    }

    @NonNull
    private ScopedSecurityContext open() {
        HttpRequest<?> currentRequest = currentRequest();
        if (currentRequest != null) {
            return new ScopedSecurityContext(get(currentRequest), false);
        }
        SecurityContext securityContext = THREAD_LOCAL_SECURITY_CONTEXT.get();
        if (securityContext != null) {
            return new ScopedSecurityContext(securityContext, false);
        }
        securityContext = new MutableSecurityContext();
        THREAD_LOCAL_SECURITY_CONTEXT.set(securityContext);
        return new ScopedSecurityContext(securityContext, true);
    }

    /**
     * A security context scope.
     */
    @Internal
    public static final class ScopedSecurityContext implements AutoCloseable {
        private final SecurityContext securityContext;
        private final boolean removeThreadLocal;

        private ScopedSecurityContext(SecurityContext securityContext, boolean removeThreadLocal) {
            this.securityContext = securityContext;
            this.removeThreadLocal = removeThreadLocal;
        }

        /**
         * @return The security context for this scope
         */
        @NonNull
        public SecurityContext getSecurityContext() {
            return securityContext;
        }

        @Override
        public void close() {
            if (removeThreadLocal) {
                THREAD_LOCAL_SECURITY_CONTEXT.remove();
            }
        }
    }
}
