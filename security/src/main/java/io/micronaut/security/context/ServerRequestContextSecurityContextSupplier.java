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
import io.micronaut.core.propagation.PropagatedContext;
import io.micronaut.core.propagation.PropagatedContextElement;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.context.ServerRequestContext;
import io.micronaut.security.authentication.Authentication;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.Optional;
import java.util.function.Supplier;

/**
 * Default {@link SecurityContextSupplier} implementation backed by the current
 * {@link ServerRequestContext}.
 *
 * @since 4.18.0
 */
@Internal
public final class ServerRequestContextSecurityContextSupplier implements SecurityContextSupplier {
    @NonNull
    public SecurityContext get(@Nullable HttpRequest<?> request) {
        return new MutableAttributeHolderSecurityContext(request);
    }

    @NonNull
    @Override
    public SecurityContext getSecurityContext() {
        return findPropagatedSecurityContext()
            .orElseGet(() -> {
                HttpRequest<?> currentRequest = currentRequest();
                return currentRequest == null ? new MutableSecurityContext() : get(currentRequest);
            });
    }

    /**
     * Convenience method to get a {@link SecurityContext} without the need of invoking
     * {@link ServerRequestContext#currentRequest()} when you already have the HTTP Request available.
     *
     * @param httpRequest HTTP Request
     * @return The current Security Context
     */
    @NonNull
    public static SecurityContext getSecurityContext(@Nullable HttpRequest<?> httpRequest) {
        if (SecurityContextHolder.INSTANCE instanceof ServerRequestContextSecurityContextSupplier supplier) {
            return supplier.findPropagatedSecurityContext().orElseGet(() -> supplier.get(httpRequest));
        }
        return SecurityContextHolder.getSecurityContext();
    }

    /**
     * Creates a propagated context with the supplied security context.
     *
     * @param securityContext The security context to propagate
     * @return The propagated context
     */
    @Internal
    @NonNull
    public static PropagatedContext withSecurityContext(@NonNull SecurityContext securityContext) {
        return PropagatedContext.getOrEmpty().plus(new PropagatedSecurityContext(securityContext));
    }

    /**
     * Creates a propagated context with a mutable security context that overrides the current authentication.
     *
     * @param authentication The authentication to propagate
     * @return The propagated context
     */
    @Internal
    @NonNull
    public static PropagatedContext withAuthentication(@NonNull Authentication authentication) {
        SecurityContext current = SecurityContextHolder.getSecurityContext();
        MutableSecurityContext securityContext = new MutableSecurityContext();
        securityContext.withAuthentication(authentication)
            .withToken(current.getToken())
            .withRejectionStatus(current.getRejectionStatus());
        return withSecurityContext(securityContext);
    }

    /**
     * Executes the supplier with the supplied propagated context.
     *
     * @param propagatedContext The propagated context
     * @param supplier The supplier
     * @param <T> The result type
     * @return The supplier result
     */
    @Internal
    @Nullable
    public static <T> T withSecurityContext(@NonNull PropagatedContext propagatedContext,
                                            @NonNull Supplier<T> supplier) {
        return propagatedContext.wrap(supplier).get();
    }

    @NonNull
    private Optional<SecurityContext> findPropagatedSecurityContext() {
        return PropagatedContext.find()
            .flatMap(context -> context.find(PropagatedSecurityContext.class))
            .map(PropagatedSecurityContext::securityContext);
    }

    @Nullable
    private HttpRequest<?> currentRequest() {
        return ServerRequestContext.currentRequest().orElse(null);
    }

    private record PropagatedSecurityContext(
        SecurityContext securityContext
    ) implements PropagatedContextElement {
    }
}
