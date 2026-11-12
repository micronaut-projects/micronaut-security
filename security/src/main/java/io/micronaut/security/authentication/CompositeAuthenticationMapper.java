/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.security.authentication;

import io.micronaut.context.annotation.Primary;
import io.micronaut.core.annotation.Internal;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Objects;

/**
 * Composite Pattern implementation of {@link AuthenticationMapper}.
 * @see <a href="https://guides.micronaut.io/latest/micronaut-patterns-composite.html">Composite Pattern</a>
 */
@Internal
@Primary
@Singleton
final class CompositeAuthenticationMapper implements AuthenticationMapper {

    private final List<AuthenticationMapper> authenticationMappers;

    /**
     * Creates a composite authentication mapper.
     *
     * @param authenticationMappers The authentication mappers to delegate to
     */
    CompositeAuthenticationMapper(List<AuthenticationMapper> authenticationMappers) {
        this.authenticationMappers = authenticationMappers;
    }

    /**
     * Attempts to map the token with the first mapper that returns an authentication.
     *
     * @param token The token to map
     * @return The mapped authentication, or {@code null} if no mapper can map the token
     */
    @Override
    public @Nullable Authentication of(@NonNull String token) {
        return authenticationMappers.stream()
            .map(mapper -> mapper.of(token))
            .filter(Objects::nonNull)
            .findFirst()
            .orElse(null);
    }
}
