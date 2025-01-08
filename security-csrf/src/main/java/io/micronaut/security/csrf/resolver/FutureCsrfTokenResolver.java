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
import io.micronaut.core.order.OrderUtil;
import io.micronaut.core.order.Ordered;
import io.micronaut.core.util.CollectionUtils;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Attempts to resolve a CSRF token from the provided request.
 * {@link FutureCsrfTokenResolver} is an {@link Ordered} api. Override the {@link #getOrder()} method to provide a custom order.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 * @param <T> request
 */
public interface FutureCsrfTokenResolver<T> extends Ordered {

    /**
     *
     * @param request The Request. Maybe an HTTP Request.
     * @return A CSRF token or an empty Optional if the token cannot be resolved.
     */
    @NonNull
    CompletableFuture<String> resolveToken(@NonNull T request);

    /**
     *
     * @param resolvers Imperative CSRF Token Resolvers
     * @param futureCsrfTokenResolvers Reactive CSRF Token Resolvers
     * @return Returns a List of {@link FutureCsrfTokenResolver} instances containing every reactive resolver plus the imperative resolvers adapted to imperative.
     * @param <T> request type
     */
    @NonNull
    static <T> List<FutureCsrfTokenResolver<T>> of(
            @NonNull List<CsrfTokenResolver<T>> resolvers,
            @NonNull List<FutureCsrfTokenResolver<T>> futureCsrfTokenResolvers) {
        List<FutureCsrfTokenResolver<T>> result = CollectionUtils.concat(futureCsrfTokenResolvers,
                resolvers.stream()
                        .map(resolver -> (FutureCsrfTokenResolver<T>) new FutureCsrfTokenResolverAdapter<>(resolver))
                        .toList());
        OrderUtil.sort(result);
        return result;
    }
}
