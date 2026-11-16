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

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;

import io.micronaut.security.config.SecurityConfiguration;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.security.token.config.TokenConfiguration;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Default implementation of {@link RolesFinder}.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
@Singleton
public class DefaultRolesFinder implements RolesFinder {

    private final TokenConfiguration tokenConfiguration;
    private final boolean rolesCaseSensitive;

    /**
     * Constructs a Roles Parser.
     * @param tokenConfiguration General Token Configuration
     */
    public DefaultRolesFinder(TokenConfiguration tokenConfiguration) {
        this(tokenConfiguration, true);
    }

    /**
     * Constructs a Roles Parser.
     * @param tokenConfiguration General Token Configuration
     * @param securityConfiguration General Security Configuration
     */
    @Inject
    public DefaultRolesFinder(TokenConfiguration tokenConfiguration, SecurityConfiguration securityConfiguration) {
        this(tokenConfiguration, securityConfiguration.isRolesCaseSensitive());
    }

    private DefaultRolesFinder(TokenConfiguration tokenConfiguration, boolean rolesCaseSensitive) {
        this.tokenConfiguration = tokenConfiguration;
        this.rolesCaseSensitive = rolesCaseSensitive;
    }

    /**
     *
     * @param rolesObject Object containing the roles
     * @return if the supplied object is {@literal null} it returns an empty list,<br />
     *         if it is a String and the {@link io.micronaut.security.token.config.TokenConfiguration#getRolesSeparator()} is not null then it will be split by the separator and returned as a list,<br />
     *         if it is an iterable, it returns a list of each element {@link Object#toString()},<br />
     *         else it returns {@link Object#toString()}
     */
    @NonNull
    private List<String> rolesAtObject(@Nullable Object rolesObject) {
        if (rolesObject == null) {
            return emptyList();
        }

        if (rolesObject instanceof CharSequence && tokenConfiguration.getRolesSeparator() != null) {
            return asList(rolesObject.toString().split(tokenConfiguration.getRolesSeparator()));
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

    @Override
    @NonNull
    public List<String> resolveRoles(@Nullable Map<String, Object> attributes) {
        return rolesAtObject(attributes != null ? attributes.get(tokenConfiguration.getRolesName()) : null);
    }

    @Override
    public boolean hasAnyRequiredRoles(@NonNull List<String> requiredRoles, @NonNull Collection<String> grantedRoles) {
        if (rolesCaseSensitive) {
            return RolesFinder.super.hasAnyRequiredRoles(requiredRoles, grantedRoles);
        }
        if (requiredRoles.isEmpty() || grantedRoles.isEmpty()) {
            return false;
        }
        Set<String> normalizedGrantedRoles = new HashSet<>(grantedRoles.size());
        boolean grantedRolesContainsNull = false;
        for (String grantedRole : grantedRoles) {
            if (grantedRole == null) {
                grantedRolesContainsNull = true;
            } else {
                normalizedGrantedRoles.add(grantedRole.toLowerCase(Locale.ROOT));
            }
        }
        for (String requiredRole : requiredRoles) {
            if (requiredRole == null) {
                if (grantedRolesContainsNull) {
                    return true;
                }
            } else if (normalizedGrantedRoles.contains(requiredRole.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }
}
