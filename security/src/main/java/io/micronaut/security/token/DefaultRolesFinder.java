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

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.authentication.Authentication;
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

    private TokenConfiguration tokenConfiguration;

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
     * @return if the supplied object is {@literal null} it returns an empty list, if it is an iterable, it returns a list of each element {@link Object#toString()}, else it returns {@link Object#toString()}
     */
    @NonNull
    protected List<String> rolesAtObject(Object rolesObject) {
        List<String> roles = new ArrayList<>();
        if (rolesObject != null) {

            if (rolesObject instanceof Iterable) {
                for (Object o : ((Iterable) rolesObject)) {
                    roles.add(o.toString());
                }
            } else {
                roles.add(rolesObject.toString());
            }

        }
        return roles;
    }

    @Override
    @NonNull
    public List<String> resolveRoles(@Nullable Map<String, Object> attributes) {
        return rolesAtObject(attributes != null ? attributes.get(tokenConfiguration.getRolesName()) : null);
    }
}
