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

import io.micronaut.context.annotation.DefaultImplementation;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;

import java.util.ArrayList;
import java.util.Collection;
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
