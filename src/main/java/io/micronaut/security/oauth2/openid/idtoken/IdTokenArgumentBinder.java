/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.openid.idtoken;

import io.micronaut.core.bind.ArgumentBinder;
import io.micronaut.core.convert.ArgumentConversionContext;
import io.micronaut.core.convert.value.MutableConvertibleValues;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.filter.OncePerRequestHttpServerFilter;
import io.micronaut.http.bind.binders.TypedRequestArgumentBinder;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.filters.SecurityFilter;

import javax.inject.Singleton;
import java.util.Optional;

/**
 * Responsible for binding the IdToken object to a route argument.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Singleton
public class IdTokenArgumentBinder implements TypedRequestArgumentBinder<IdToken> {

    @Override
    public Argument<IdToken> argumentType() {
        return Argument.of(IdToken.class);
    }

    @Override
    public BindingResult<IdToken> bind(ArgumentConversionContext<IdToken> context, HttpRequest<?> source) {
        if (source.getAttributes().contains(OncePerRequestHttpServerFilter.getKey(SecurityFilter.class))) {
            MutableConvertibleValues<Object> attrs = source.getAttributes();
            Optional<Authentication> existing = attrs.get(SecurityFilter.AUTHENTICATION, Authentication.class);

            if (existing.isPresent()) {
                return (BindingResult) () -> {
                    IdToken idToken = new IdTokenAuthenticationAdapter(existing.get());
                    return Optional.of(idToken);
                };
            }
        }

        return ArgumentBinder.BindingResult.EMPTY;
    }
}
