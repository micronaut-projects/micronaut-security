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
package io.micronaut.security.csrf.validator;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.order.Ordered;

/**
 * CSRF Token Validation.
 * @author Sergio del Amo
 * @since 4.11.0
 * @param <T> request
 */
@FunctionalInterface
public interface CsrfTokenValidator<T> extends Ordered {
    /**
     * Given a CSRF Token, validates whether it is valid.
     * @param request Request
     * @param token CSRF Token
     * @return Whether the CSRF token is valid
     */
    boolean validateCsrfToken(@NonNull T request, @NonNull String token);
}
