/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.security.ojdbc.extensions;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.authentication.Authentication;
import org.jspecify.annotations.NonNull;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Utility methods for deriving OJDBC provider values from Micronaut Security roles.
 */
@Experimental
@Internal
public final class RolesUtils {
    private RolesUtils() {

    }

    /**
     * Returns the unique roles from an authentication that start with the given prefix.
     *
     * <p>The prefix is removed from each matching role, and the remaining value is
     * trimmed before it is added to the returned set. Null roles, roles without the
     * prefix, and roles whose remaining value is blank are ignored.
     *
     * @param prefix prefix to match and remove
     * @param authentication authentication whose roles should be inspected
     *
     * @return matching roles without the prefix, or an empty set if none match
     */
    static @NonNull Set<String> getPrefixedRoles(@NonNull String prefix, @NonNull Authentication authentication) {
        Set<String> authorities = null;
        for (String authority : authentication.getRoles()) {
            if (authority == null) {
                continue;
            }
            if (! authority.startsWith(prefix)) {
                continue;
            }
            authority = authority.substring(prefix.length()).trim();
            if (authority.isEmpty()) {
                continue;
            }
            if (authorities == null) {
                authorities = new HashSet<>();
            }
            authorities.add(authority);
        }
        return authorities == null ? Collections.emptySet() : authorities;
    }
}
