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

import tools.jackson.databind.annotation.JsonDeserialize;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.io.Serializable;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Represents the state of an authentication.
 *
 * @author James Kleeh
 * @since 1.0
 */
@JsonDeserialize(as = ClientAuthentication.class)
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
     * @return Any roles associated with the authentication
     */
    @NonNull
    default Collection<String> getRoles() {
        return Collections.emptyList();
    }

    /**
     * Builds an {@link Authentication} instance for the user.
     * @param username User's name
     * @return An {@link Authentication} for the User
     */
    @NonNull
    static Authentication build(@NonNull String username) {
        return Authentication.build(username, null, null);
    }

    /**
     * Builds an {@link Authentication} instance for the user.
     * @param username User's name
     * @param roles User's roles
     * @return An {@link Authentication} for the User
     */
    @NonNull
    static Authentication build(@NonNull String username,
                                @NonNull Collection<String> roles) {
        return Authentication.build(username, roles, null);
    }


    /**
     * Builds an {@link Authentication} instance for the user.
     * @param username User's name
     * @param attributes User's attributes
     * @return An {@link Authentication} for the User
     */
    @NonNull
    static Authentication build(@NonNull String username,
                                @NonNull Map<String, Object> attributes) {
        return new ServerAuthentication(username, null, attributes);
    }

    /**
     * Builds an {@link Authentication} instance for the user.
     * @param username User's name
     * @param roles User's roles
     * @param attributes User's attributes
     * @return An {@link Authentication} for the User
     */
    @NonNull
    static Authentication build(@NonNull String username,
                                @Nullable Collection<String> roles,
                                @Nullable Map<String, Object> attributes) {
        return new ServerAuthentication(username, roles, attributes);
    }

    /**
     * Creates an authentication with the supplied attributes, optionally appending them to the current attributes.
     *
     * @param attributes User's attributes
     * @param append Whether to append the attributes to the current attributes
     * @return An {@link Authentication} with the supplied attributes
     * @since 5.1.0
     */
    default @NonNull Authentication withAttributes(@NonNull Map<String, Object> attributes, boolean append) {
        if (!append) {
            return withAttributes(attributes);
        }
        Map<String, Object> newAttributes = new LinkedHashMap<>(getAttributes());
        newAttributes.putAll(attributes);
        return withAttributes(newAttributes);
    }

    /**
     * Creates an authentication with the supplied attributes.
     *
     * @param attributes User's attributes
     * @return An {@link Authentication} with the supplied attributes
     * @since 5.1.0
     */
    default @NonNull Authentication withAttributes(@NonNull Map<String, Object> attributes) {
        return Authentication.build(getName(), getRoles(), attributes);
    }

    /**
     * Creates an authentication with the supplied roles, optionally appending them to the current roles.
     *
     * @param roles User's roles
     * @param append Whether to append the roles to the current roles
     * @return An {@link Authentication} with the supplied roles
     * @since 5.1.0
     */
    default @NonNull Authentication withRoles(@NonNull Collection<String> roles, boolean append) {
        if (!append) {
            return withRoles(roles);
        }
        Collection<String> newRoles = new ArrayList<>(getRoles());
        newRoles.addAll(roles);
        return withRoles(newRoles);
    }

    /**
     * Creates an authentication with the supplied roles.
     *
     * @param roles User's roles
     * @return An {@link Authentication} with the supplied roles
     * @since 5.1.0
     */
    default @NonNull Authentication withRoles(@NonNull Collection<String> roles) {
        return Authentication.build(getName(), roles, getAttributes());
    }

    /**
     * Creates an authentication with the supplied user name.
     *
     * @param username User's name
     * @return An {@link Authentication} with the supplied user name
     * @since 5.1.0
     */
    default @NonNull Authentication withUsername(@NonNull String username) {
        return Authentication.build(username, getRoles(), getAttributes());
    }
}
