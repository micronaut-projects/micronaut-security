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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.security.token.config.TokenConfiguration;
import jakarta.inject.Singleton;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

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
     * @param rolesObject Object containing the roles
     * @return if the supplied object is {@literal null} it returns an empty list,<br />
     *         if it is a String and the {@link io.micronaut.security.token.config.TokenConfiguration#getRolesSeparator()} is not null then it will be split by the separator and returned as a list,<br />
     *         if it is an iterable, it returns a list of each element {@link Object#toString()},<br />
     *         else it returns {@link Object#toString()}
     */
    @NonNull
    private List<String> rolesAtObject(@Nullable Object rolesObject) {
        return switch (rolesObject) {
            case null -> emptyList();
            case CharSequence _ when tokenConfiguration.getRolesSeparator() != null ->
                asList(rolesObject.toString().split(Pattern.quote(tokenConfiguration.getRolesSeparator())));
            case Iterable<?> iterable -> {
                List<String> roles = new ArrayList<>();
                for (Object o : iterable) {
                    roles.add(o.toString());
                }
                yield roles;
            }
            default -> singletonList(rolesObject.toString());
        };
    }

    @Nullable
    private Object findRolesObject(@NonNull Map<String, Object> attributes) {
        if (tokenConfiguration.getRolesNameSeparator() == null) {
            return attributes.get(tokenConfiguration.getRolesName());
        }
        String[] rolesNameKeys = tokenConfiguration.getRolesName().split(Pattern.quote(tokenConfiguration.getRolesNameSeparator()));
        Object rolesObject = attributes;
        for (String rolesNameKey : rolesNameKeys) {
            rolesObject = switch (rolesObject) {
                case Map<?, ?> map -> map.get(rolesNameKey);
                case null, default -> null;
            };
        }
        return rolesObject;
    }

    @Override
    @NonNull
    public List<String> resolveRoles(@Nullable Map<String, Object> attributes) {
        return rolesAtObject(attributes != null ? findRolesObject(attributes) : null);
    }
}
