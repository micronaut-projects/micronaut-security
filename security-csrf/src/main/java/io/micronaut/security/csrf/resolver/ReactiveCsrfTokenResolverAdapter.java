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

import io.micronaut.core.async.publisher.Publishers;
import org.reactivestreams.Publisher;

/**
 * Adapter from {@link CsrfTokenResolver} to {@link ReactiveCsrfTokenResolver}.
 * @param <T> Request
 */
public class ReactiveCsrfTokenResolverAdapter<T> implements ReactiveCsrfTokenResolver<T> {

    private final CsrfTokenResolver<T> csrfTokenResolver;

    /**
     *
     * @param csrfTokenResolver CSRF Token resolver
     */
    public ReactiveCsrfTokenResolverAdapter(CsrfTokenResolver<T> csrfTokenResolver) {
        this.csrfTokenResolver = csrfTokenResolver;
    }

    @Override
    public Publisher<String> resolveToken(T request) {
        return csrfTokenResolver.resolveToken(request)
                .map(Publishers::just)
                .orElseGet(Publishers::empty);
    }

    @Override
    public int getOrder() {
        return csrfTokenResolver.getOrder();
    }
}
