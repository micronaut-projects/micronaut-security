/*
 * Copyright 2017-2024 original authors
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
package io.micronaut.security.csrf.resolver;

import io.micronaut.core.annotation.NonNull;

import java.util.concurrent.CompletableFuture;

/**
 * Adapter from {@link CsrfTokenResolver} to {@link FutureCsrfTokenResolver}.
 * @param <T> Request
 */
final class FutureCsrfTokenResolverAdapter<T> implements FutureCsrfTokenResolver<T> {

    private final CsrfTokenResolver<T> csrfTokenResolver;

    /**
     *
     * @param csrfTokenResolver CSRF Token resolver
     */
    public FutureCsrfTokenResolverAdapter(CsrfTokenResolver<T> csrfTokenResolver) {
        this.csrfTokenResolver = csrfTokenResolver;
    }

    @Override
    @NonNull
    public CompletableFuture<String> resolveToken(@NonNull  T request) {
        return CompletableFuture.completedFuture(csrfTokenResolver.resolveToken(request).orElse(null));
    }

    @Override
    public int getOrder() {
        return csrfTokenResolver.getOrder();
    }
}
