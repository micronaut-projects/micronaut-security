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
package io.micronaut.security.token;

import java.util.ArrayList;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.context.annotation.DefaultImplementation;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.authentication.Authentication;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Retrieves roles from token claims.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
@DefaultImplementation(DefaultRolesFinder.class)
public interface RolesFinder {

    /**
     * Retrieves the list of roles from the provided claims.
     *
     * @param claims The claims of the token.
     * @return The granted roles.
     * @deprecated use {@link RolesFinder#resolveRoles(Map)} instead.
     */
    @Deprecated
    @NonNull
    default List<String> findInClaims(@NonNull Claims claims) {
        Map<String, Object> atttributes = new HashMap<>();
        for (String k : claims.names()) {
            atttributes.put(k, claims.get(k));
        }
        return resolveRoles(atttributes);
    }

    /**
     *
     * @param requiredRoles The list of roles required to be authorized
     * @param authentication The authentication
     * @return true if any of the Authentication's roles is in the required roles list.
     * @deprecated Use {@link RolesFinder#hasAnyRequiredRoles(List, Map)} instead.
     */
    @Deprecated
    default boolean hasAnyRequiredRoles(@NonNull List<String> requiredRoles, @NonNull Authentication authentication) {
        return hasAnyRequiredRoles(requiredRoles, authentication.getRoles());
    }

    /**
     *
     * @param requiredRoles The list of roles required to be authorized
     * @param claims The claims of the token.
     * @return true if any the roles specified in the claims is in the required roles list.
     * @deprecated Use {@link RolesFinder#hasAnyRequiredRoles(List, Map)} instead.
     */
    @Deprecated
    default boolean hasAnyRequiredRoles(@NonNull List<String> requiredRoles, @NonNull Claims claims) {
        return hasAnyRequiredRoles(requiredRoles, findInClaims(claims));
    }

    /**
     *
     * @param requiredRoles The list of roles required to be authorized
     * @param attributes User's attributes
     * @return true if any the roles specified in the attributes is in the required roles list.
     */
    default boolean hasAnyRequiredRoles(@NonNull List<String> requiredRoles, @Nullable Map<String, Object> attributes) {
        return hasAnyRequiredRoles(requiredRoles, resolveRoles(attributes));
    }

    /**
     *
     * @param requiredRoles The list of roles required to be authorized
     * @param grantedRoles The list of roles granted to the user
     * @return true if any of the granted roles is in the required roles list.
     */
    default boolean hasAnyRequiredRoles(@NonNull List<String> requiredRoles, @NonNull Collection<String> grantedRoles) {
        List<String> l = new ArrayList<>(requiredRoles);
        l.retainAll(grantedRoles);
        return !l.isEmpty();
    }

    /**
     * Retrieves the list of roles from the User Attributes.
     *
     * @param attributes User's attributes
     * @return The granted roles.
     */
    @NonNull
    List<String> resolveRoles(@Nullable Map<String, Object> attributes);
}
