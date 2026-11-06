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
package io.micronaut.security.csrf.generator;

import io.micronaut.context.annotation.DefaultImplementation;
import io.micronaut.security.authentication.Authentication;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * CSRF token Generation.
 * @author Sergio del Amo
 * @since 4.11.0
 * @param <T> Request
 */
@DefaultImplementation(DefaultCsrfTokenGenerator.class)
@FunctionalInterface
public interface CsrfTokenGenerator<T> {
    /**
     * Generates a CSRF Token.
     * @param request Request
     * @return A CSRF Token.
     */
    @NonNull
    String generateCsrfToken(@NonNull T request);

    /**
     * Generates a CSRF Token bound to the supplied authenticated user. Use this method when the request does not carry the
     * authentication yet, for example while handling a login. The default implementation ignores the authentication and
     * delegates to {@link #generateCsrfToken(Object)}.
     * @param request Request
     * @param authentication The authenticated user's representation or {@code null} for an anonymous request
     * @return A CSRF Token.
     * @since 5.5.2
     */
    @NonNull
    default String generateCsrfToken(@NonNull T request, @Nullable Authentication authentication) {
        return generateCsrfToken(request);
    }
}
