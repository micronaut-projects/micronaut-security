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
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.bind.binders.TypedRequestArgumentBinder;
import io.micronaut.security.filters.SecurityFilter;
import java.security.Principal;
import java.util.Optional;

/**
 * Binds the authentication object to a route argument.
 *
 * @param <A> the {@link Principal} type
 * @author Burt Beckwith
 * @since 3.2
 */
public abstract class AbstractPrincipalArgumentBinder<A extends Principal> implements TypedRequestArgumentBinder<A> {

    private final Class<A> authenticationClass;
    private final Argument<A> argumentType;

    protected AbstractPrincipalArgumentBinder(Class<A> authenticationClass) {
        this.authenticationClass = authenticationClass;
        argumentType = Argument.of(authenticationClass);
    }

    @SuppressWarnings("unchecked")
    @Override
    public BindingResult<A> bind(ArgumentConversionContext<A> context,
                                 HttpRequest<?> source) {

        if (!source.getAttributes().contains(SecurityFilter.KEY)) {
            return BindingResult.UNSATISFIED;
        }

        final Optional<A> existing = source.getUserPrincipal(authenticationClass);
        return existing.isPresent() ? (() -> existing) : BindingResult.EMPTY;
    }

    @Override
    public Argument<A> argumentType() {
        return argumentType;
    }
}
