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
package io.micronaut.security.csrf.repository;

import io.micronaut.core.annotation.Indexed;
import org.jspecify.annotations.NonNull;
import io.micronaut.core.order.Ordered;

import java.util.Optional;

/**
 * Repository API for CSRF Tokens.
 * {@link CsrfTokenRepository} is an {@link Ordered} api. Override the {@link #getOrder()} method to provide a custom order.
 * Repositories are consulted in order and the first repository holding a CSRF token for the request is authoritative when validating the token supplied in the request.
 * @param <T> Request
 */
@Indexed(CsrfTokenRepository.class)
@FunctionalInterface
public interface CsrfTokenRepository<T> extends Ordered {
    /**
     *
     * @param request Request
     * @return A CSRF token or an empty optional.
     */
    @NonNull
    Optional<String> findCsrfToken(@NonNull T request);
}
