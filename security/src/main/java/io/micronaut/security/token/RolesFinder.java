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

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;

/**
 * Retrieves roles from token claims.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
public interface RolesFinder {

    /**
     * Retrieves the list of roles from the provided claims.
     *
     * @param claims The claims of the token.
     * @return The granted roles.
     */
    @Nonnull
    List<String> findInClaims(@Nonnull Claims claims);

    /**
     *
     * @param requiredRoles The list of roles required to be authorized
     * @param grantedRoles The list of roles granted to the user
     * @return true if any of the granted roles is in the required roles list.
     */
    default boolean hasAnyRequiredRoles(List<String> requiredRoles, List<String> grantedRoles) {
        List<String> l = new ArrayList<>(requiredRoles);
        l.retainAll(grantedRoles);
        return !l.isEmpty();
    }
}
