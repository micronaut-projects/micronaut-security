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

import io.micronaut.context.annotation.Requires;
import io.micronaut.security.csrf.repository.CsrfTokenRepository;
import jakarta.inject.Singleton;

/**
 * {@link CsrfTokenValidator} implementation that uses a {@link CsrfTokenRepository}.
 * First attempts to retrieve a token from a {@link CsrfTokenRepository} and if found validates it against the supplied token.
 * @param <T> Request
 * @since 4.11.0
 * @author Sergio del Amo
 */
@Requires(bean = CsrfTokenRepository.class)
@Singleton
public class RepositoryCsrfTokenValidator<T> implements CsrfTokenValidator<T> {
    private final CsrfTokenRepository<T> csrfTokenRepository;

    public RepositoryCsrfTokenValidator(CsrfTokenRepository<T> csrfTokenRepository) {
        this.csrfTokenRepository = csrfTokenRepository;
    }

    @Override
    public boolean validateCsrfToken(T request, String token) {
        return csrfTokenRepository.findCsrfToken(request)
                .map(storedToken -> storedToken.equals(token))
                .orElse(false);
    }
}
