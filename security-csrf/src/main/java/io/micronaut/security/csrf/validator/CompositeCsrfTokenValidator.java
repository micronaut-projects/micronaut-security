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

import io.micronaut.context.annotation.Primary;
import io.micronaut.core.annotation.NonNull;
import jakarta.inject.Singleton;
import java.util.List;

/**
 * Composite Pattern implementation of {@link CsrfTokenValidator}.
 * @see <a href="https://guides.micronaut.io/latest/micronaut-patterns-composite.html">Composite Pattern</a>
 * @param <T> Request
 */
@Primary
@Singleton
public class CompositeCsrfTokenValidator<T> implements CsrfTokenValidator<T> {

    private final List<CsrfTokenValidator<T>> csrfTokenValidators;

    /**
     *
     * @param csrfTokenValidators CSRF Token Validators
     */
    public CompositeCsrfTokenValidator(List<CsrfTokenValidator<T>> csrfTokenValidators) {
        this.csrfTokenValidators = csrfTokenValidators;
    }

    @Override
    public boolean validateCsrfToken(@NonNull T request, @NonNull String csrfToken) {
        for (CsrfTokenValidator<T> csrfTokenValidator : csrfTokenValidators) {
            if (csrfTokenValidator.validateCsrfToken(request, csrfToken)) {
                return true;
            }
        }
        return false;
    }
}
