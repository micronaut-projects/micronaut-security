/*
 * Copyright 2017-2021 original authors
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

import com.fasterxml.jackson.annotation.JsonValue;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.token.config.TokenConfiguration;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * An implementation of the {@link Authentication} interfaced intended to
 * be used on the server side to create authentication objects from
 * user data found through any means.
 *
 * @author James Kleeh
 * @since 3.0.0
 */
public class ServerAuthentication implements Authentication {

    private static final String JSON_KEY_NAME = "name";
    private static final String JSON_KEY_ATTRIBUTES = "attributes";
    private final String name;
    private final Collection<String> roles;
    private final Map<String, Object> attributes;

    public ServerAuthentication(@NonNull String name,
                                @Nullable Collection<String> roles,
                                @Nullable Map<String, Object> attributes) {
        this.name = name;
        this.roles = (roles == null || roles.isEmpty()) ? new ArrayList<>() : roles;
        this.attributes = attributes == null ? Collections.emptyMap() : attributes;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    @NonNull
    public Map<String, Object> getAttributes() {
        return Collections.unmodifiableMap(attributes);
    }

    @NonNull
    @Override
    public Collection<String> getRoles() {
        return Collections.unmodifiableCollection(roles);
    }

    /**
     * @return A Map to be used a JSON representation of the object
     */
    @JsonValue
    public Map<String, Object> toJson() {
        Map<String, Object> json = new HashMap<>();
        json.put(JSON_KEY_NAME, getName());
        Map<String, Object> jsonAttributes = new HashMap<>(getAttributes());
        jsonAttributes.putIfAbsent(TokenConfiguration.DEFAULT_ROLES_NAME, getRoles());
        json.put(JSON_KEY_ATTRIBUTES, jsonAttributes);
        return json;
    }
}
