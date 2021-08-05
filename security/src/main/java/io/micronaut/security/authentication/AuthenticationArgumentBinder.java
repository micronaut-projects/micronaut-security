/*
 * Copyright 2017-2020 original authors
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

import jakarta.inject.Singleton;
import java.util.Optional;

/**
 * Responsible for binding the authentication object to a route argument.
 *
 * @author James Kleeh
 * @since 1.0
 */
@Singleton
public class AuthenticationArgumentBinder implements TypedRequestArgumentBinder<Authentication> {

    @Override
    public Argument<Authentication> argumentType() {
        return Argument.of(Authentication.class);
    }

    @Override
    public BindingResult<Authentication> bind(ArgumentConversionContext<Authentication> context, HttpRequest<?> source) {
        if (source.getAttributes().contains(SecurityFilter.KEY)) {
            final Optional<Authentication> existing = source.getUserPrincipal(Authentication.class);
            if (existing.isPresent()) {
                return () -> existing;
            } else {
                return BindingResult.EMPTY;
            }
        } else {
            return BindingResult.UNSATISFIED;
        }
    }
}
