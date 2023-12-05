/*
 * Copyright 2017-2023 original authors
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

import io.micronaut.core.convert.ArgumentConversionContext;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.bind.binders.AnnotatedRequestArgumentBinder;
import io.micronaut.security.annotation.User;
import io.micronaut.security.filters.SecurityFilter;
import jakarta.inject.Singleton;

import java.security.Principal;
import java.util.Optional;

/**
 * Binds the authentication object to a route argument annotated with {@link User}.
 *
 * @param <T> The bound subtype of {@link Principal}
 * @author Jeremy Grelle
 * @since 4.5.0
 */
@Singleton
public class UserArgumentBinder<T extends Principal> implements AnnotatedRequestArgumentBinder<User, T> {

    @Override
    public Class<User> getAnnotationType() {
        return User.class;
    }

    @Override
    public BindingResult<T> bind(ArgumentConversionContext<T> context, HttpRequest<?> source) {
        if (!source.getAttributes().contains(SecurityFilter.KEY)) {
            return BindingResult.unsatisfied();
        }

        final Optional<T> existing = source.getUserPrincipal(context.getArgument().getType());
        return existing.isPresent() ? (() -> existing) : BindingResult.empty();
    }
}
