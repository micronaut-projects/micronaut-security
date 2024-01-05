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
package io.micronaut.security.converters;

import io.micronaut.core.annotation.Internal;
import io.micronaut.core.convert.ConversionContext;
import io.micronaut.core.convert.TypeConverter;
import io.micronaut.security.annotation.CreatedBy;
import io.micronaut.security.annotation.UpdatedBy;
import io.micronaut.security.authentication.Authentication;

import java.security.Principal;
import java.util.Optional;

/**
 * A {@link Principal} to {@code String} converter.
 *
 * This is intended as the default implementation for conversion of the current {@link Authentication} to {@code String}
 * entity fields annotated with either {@link CreatedBy} or {@link UpdatedBy},
 * and simply converts to {@link Principal#getName()}.
 * This implementation may be replaced for custom mapping of a unique {@link String} identifier, or additional converters
 * may be provided for mapping to more complex types.
 *
 * @author Jeremy Grelle
 * @since 4.5.0
 */
@Internal
class PrincipalToStringConverter implements TypeConverter<Principal, String> {

    /**
     *
     * @param principal  The source principal
     * @param targetType The target type being converted to
     * @param context    The {@link ConversionContext}
     * @return The converted type or empty if the conversion is not possible
     */
    @Override
    public Optional<String> convert(Principal principal, Class<String> targetType, ConversionContext context) {
        return Optional.ofNullable(principal.getName());
    }
}
