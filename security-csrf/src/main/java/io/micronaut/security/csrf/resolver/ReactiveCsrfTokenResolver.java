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
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.core.order.OrderUtil;
import io.micronaut.core.order.Ordered;
import org.reactivestreams.Publisher;

import java.util.ArrayList;
import java.util.List;

/**
 * Attempts to resolve a CSRF token from the provided request.
 * {@link ReactiveCsrfTokenResolver} is an {@link Ordered} api. Override the {@link #getOrder()} method to provide a custom order.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 * @param <T> request
 */
public interface ReactiveCsrfTokenResolver<T> extends Ordered {

    /**
     *
     * @param request The Request. Maybe an HTTP Request.
     * @return A CSRF token or an empty Optional if the token cannot be resolved.
     */
    @SingleResult
    @NonNull
    Publisher<String> resolveToken(T request);

    /**
     *
     * @param resolvers Imperative CSRF Token Resolvers
     * @param reactiveCsrfTokenResolvers Reactive CSRF Token Resolvers
     * @return Returns a List of {@link ReactiveCsrfTokenResolver} instances containing every reactive resolver plus the imperative resolvers adapted to imperative.
     * @param <T>
     */
    static <T> List<ReactiveCsrfTokenResolver<T>> of(List<CsrfTokenResolver<T>> resolvers,
                                                     List<ReactiveCsrfTokenResolver<T>> reactiveCsrfTokenResolvers) {
        List<ReactiveCsrfTokenResolver<T>> result  = new ArrayList<>();
        result.addAll(reactiveCsrfTokenResolvers);
        result.addAll(resolvers.stream().map(ReactiveCsrfTokenResolverAdapter::new).toList());
        OrderUtil.sort(result);
        return result;
    }
}
