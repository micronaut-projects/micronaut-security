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

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.security.token.config.TokenConfiguration;
import jakarta.inject.Singleton;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Default implementation of {@link RolesFinder}.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
@Singleton
public class DefaultRolesFinder implements RolesFinder {

    private final TokenConfiguration tokenConfiguration;

    /**
     * Constructs a Roles Parser.
     * @param tokenConfiguration General Token Configuration
     */
    public DefaultRolesFinder(TokenConfiguration tokenConfiguration) {
        this.tokenConfiguration = tokenConfiguration;
    }

    /**
     *
     * @param rolesObject Object containing the roles
     * @return if the supplied object is {@literal null} it returns an empty list,<br />
     *         if it is a String and the {@link io.micronaut.security.token.config.TokenConfiguration#getRolesSeparator()} is not null or empty then it will be split by the literal separator, each role trimmed and empty entries dropped, and returned as a list,<br />
     *         if it is an iterable, it returns a list of each element {@link Object#toString()},<br />
     *         else it returns {@link Object#toString()}
     */
    @NonNull
    private List<String> rolesAtObject(@Nullable Object rolesObject) {
        if (rolesObject == null) {
            return emptyList();
        }

        String separator = tokenConfiguration.getRolesSeparator();
        if (rolesObject instanceof CharSequence && separator != null && !separator.isEmpty()) {
            return splitRoles(rolesObject.toString(), separator);
        }

        if (rolesObject instanceof Iterable) {
            List<String> roles = new ArrayList<>();
            for (Object o : ((Iterable<?>) rolesObject)) {
                roles.add(o.toString());
            }
            return roles;
        }

        return singletonList(rolesObject.toString());
    }

    /**
     * Splits the value on the literal separator, trims each entry and drops empty entries.
     *
     * @param value The roles value
     * @param separator The literal, non-empty separator
     * @return The list of roles
     */
    @NonNull
    private static List<String> splitRoles(@NonNull String value, @NonNull String separator) {
        List<String> roles = new ArrayList<>();
        int start = 0;
        while (start <= value.length()) {
            int index = value.indexOf(separator, start);
            int end = index == -1 ? value.length() : index;
            String role = value.substring(start, end).trim();
            if (!role.isEmpty()) {
                roles.add(role);
            }
            if (index == -1) {
                break;
            }
            start = index + separator.length();
        }
        return roles;
    }

    @Override
    @NonNull
    public List<String> resolveRoles(@Nullable Map<String, Object> attributes) {
        return rolesAtObject(attributes != null ? attributes.get(tokenConfiguration.getRolesName()) : null);
    }
}
