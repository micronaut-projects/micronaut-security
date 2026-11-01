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
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.propagation.PropagatedContext;
import io.micronaut.core.propagation.PropagatedContextElement;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.context.ServerHttpRequestContext;
import io.micronaut.http.context.ServerRequestContext;
import io.micronaut.security.authentication.Authentication;

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
        SecurityContext securityContext = new MutableAttributeHolderSecurityContext(request);
        return PropagatedContext.find()
            .flatMap(context -> context.find(PropagatedAuthentication.class))
            .filter(propagated -> propagated.request() == request)
            .<SecurityContext>map(propagated -> new PropagatedAuthenticationSecurityContext(securityContext, propagated.authentication()))
            .orElse(securityContext);
    }

    @NonNull
    @Override
    public SecurityContext getSecurityContext() {
        return get(ServerRequestContext.currentRequest().orElse(null));
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
     * Creates a propagated context bound to the supplied request and authentication.
     * <p>
     * While the returned context is propagated, code resolving the {@link SecurityContext} through
     * {@link SecurityContextHolder}, or the request through {@link ServerRequestContext}, sees the supplied
     * request and authentication regardless of the context currently bound to the thread. Reactive security
     * processing may resume on a thread bound to another request's context, for example when several requests
     * wait for the same asynchronous token validation result.
     *
     * @param request The request being processed
     * @param authentication The authentication of the request, or {@code null} for an anonymous request
     * @return The propagated context
     * @since 4.18.2
     */
    @Internal
    @NonNull
    public static PropagatedContext withRequestAndAuthentication(@NonNull HttpRequest<?> request,
                                                                 @Nullable Authentication authentication) {
        return PropagatedContext.getOrEmpty()
            .plus(new ServerHttpRequestContext(request))
            .plus(new PropagatedAuthentication(request, authentication));
    }

    /**
     * The authentication bound to a request by {@link #withRequestAndAuthentication(HttpRequest, Authentication)}.
     *
     * @param request The request
     * @param authentication The authentication of the request, or {@code null} for an anonymous request
     */
    private record PropagatedAuthentication(HttpRequest<?> request,
                                            Authentication authentication) implements PropagatedContextElement {
    }

    /**
     * A {@link SecurityContext} whose authentication is the one bound by
     * {@link #withRequestAndAuthentication(HttpRequest, Authentication)}; everything else is read from and written to
     * the request attributes.
     */
    private static final class PropagatedAuthenticationSecurityContext implements SecurityContext {
        private final SecurityContext delegate;
        @Nullable
        private final Authentication authentication;

        private PropagatedAuthenticationSecurityContext(SecurityContext delegate, @Nullable Authentication authentication) {
            this.delegate = delegate;
            this.authentication = authentication;
        }

        @Override
        @Nullable
        public Authentication getAuthentication() {
            return authentication;
        }

        @Override
        @Nullable
        public String getToken() {
            return delegate.getToken();
        }

        @Override
        @NonNull
        public SecurityContext withAuthentication(@Nullable Authentication authentication) {
            delegate.withAuthentication(authentication);
            return this;
        }

        @Override
        @NonNull
        public SecurityContext withToken(@Nullable String token) {
            delegate.withToken(token);
            return this;
        }

        @Override
        @NonNull
        public SecurityContext withRejectionStatus(@Nullable Integer statusCode) {
            delegate.withRejectionStatus(statusCode);
            return this;
        }

        @Override
        @Nullable
        public Integer getRejectionStatus() {
            return delegate.getRejectionStatus();
        }

        @Override
        public void clear() {
            delegate.clear();
        }
    }
}
