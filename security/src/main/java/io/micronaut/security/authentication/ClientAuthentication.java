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
package io.micronaut.security.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.Introspected;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.security.token.config.TokenConfiguration;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * An implementation of the Authentication interface intended to be used
 * by clients that deserialize token information into an authentication.
 *
 * @author James Kleeh
 * @since 3.0.0
 */
@Introspected
public class ClientAuthentication implements Authentication {

    private final String name;
    private final Map<String, Object> attributes;

    /**
     *
     * @param name The name of the authentication
     * @param attributes The attributes for the authentication
     */
    @JsonCreator
    public ClientAuthentication(@JsonProperty("name") String name,
                                @JsonProperty("attributes") Map<String, Object> attributes) {
        this.name = name;
        this.attributes = attributes;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    @NonNull
    public Map<String, Object> getAttributes() {
        return new HashMap<>(attributes);
    }

    /**
     * This implementation relies on a key being stored in the claims called "rolesKey"
     * that stores the key where the roles are stored. This claim is provided by the
     * claims set generator in the jwt module.
     *
     * @return Any roles found in the attributes
     */
    @NonNull
    @Override
    @JsonIgnore
    public Collection<String> getRoles() {
        if (attributes != null) {
            Object rolesKey = attributes.get("rolesKey");
            if (rolesKey == null) {
                rolesKey = TokenConfiguration.DEFAULT_ROLES_NAME;
            }
            Object roleAttribute = attributes.get(rolesKey.toString());
            if (roleAttribute != null) {
                List<String> roles = new ArrayList<>();
                if (roleAttribute instanceof Iterable) {
                    for (Object o : ((Iterable) roleAttribute)) {
                        roles.add(o.toString());
                    }
                } else {
                    roles.add(roleAttribute.toString());
                }
                return roles;
            }
        }
        return Collections.emptyList();
    }
}
