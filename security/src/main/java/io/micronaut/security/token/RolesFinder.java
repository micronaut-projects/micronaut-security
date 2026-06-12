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
package io.micronaut.security.token;

import io.micronaut.context.annotation.DefaultImplementation;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Resolves roles from authentication attributes and compares granted roles with
 * roles required by a security rule.
 * <p>
 * Micronaut Security uses this interface when creating an
 * {@link io.micronaut.security.authentication.Authentication} from token
 * attributes and when checking whether an authenticated user has one of the
 * roles required by a route or intercept-url-map entry. Applications can
 * replace the default implementation when roles are stored in a custom claim
 * structure.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
@DefaultImplementation(DefaultRolesFinder.class)
public interface RolesFinder {

    /**
     * Resolves the granted roles from the supplied attributes and checks whether
     * they contain any required role.
     *
     * @param requiredRoles The roles required to be authorized
     * @param attributes The user's authentication attributes
     * @return true if any resolved granted role is present in the required roles
     */
    default boolean hasAnyRequiredRoles(@NonNull List<String> requiredRoles, @Nullable Map<String, Object> attributes) {
        return hasAnyRequiredRoles(requiredRoles, resolveRoles(attributes));
    }

    /**
     * Checks whether the granted roles contain any required role.
     *
     * @param requiredRoles The roles required to be authorized
     * @param grantedRoles The roles granted to the user
     * @return true if any granted role is present in the required roles
     */
    default boolean hasAnyRequiredRoles(@NonNull List<String> requiredRoles, @NonNull Collection<String> grantedRoles) {
        List<String> l = new ArrayList<>(requiredRoles);
        l.retainAll(grantedRoles);
        return !l.isEmpty();
    }

    /**
     * Resolves granted roles from the user's authentication attributes.
     * <p>
     * Implementations should return an empty list when the attributes are
     * {@code null} or no roles can be resolved.
     *
     * @param attributes The user's authentication attributes
     * @return The granted roles
     */
    @NonNull
    List<String> resolveRoles(@Nullable Map<String, Object> attributes);
}
