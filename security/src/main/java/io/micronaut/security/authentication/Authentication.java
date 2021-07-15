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

import io.micronaut.core.annotation.NonNull;
import java.io.Serializable;
import java.security.Principal;
import java.util.Map;
import java.util.Optional;

/**
 * Represents the state of an authentication.
 *
 * @author James Kleeh
 * @since 1.0
 */
public interface Authentication extends Principal, Serializable {

    /**
     * In order to correctly implement the {@link Serializable} specification, this map
     * should be {@literal Map<String, Serializable>}, however that would place a burden on
     * those not requiring serialization, forcing their values to conform to that spec.
     *
     * This is left intentionally as Object in order to meet both use cases and those
     * requiring serialization must ensure all values in the map implement {@link Serializable}.
     *
     * @return Any additional attributes in the authentication
     */
    @NonNull
    Map<String, Object> getAttributes();

    /**
     * Retrieves an explicitly typed attribute value.
     *
     * @param name the name of the attribute
     * @param clazz the expected class of the attribute
     * @param <T> the expected type of the attribute
     * @return the typed attribute or null if it doesn't exist or the type is not correct
     */
    default <T> Optional<T> getAttribute(String name, @NonNull Class<T> clazz) {
        return Optional.ofNullable(getAttributes().get(name))
            .filter(clazz::isInstance)
            .map(clazz::cast);
    }
}
