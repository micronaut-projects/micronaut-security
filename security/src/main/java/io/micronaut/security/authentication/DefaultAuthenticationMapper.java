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
package io.micronaut.security.authentication;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.security.token.config.TokenConfiguration;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Requires(classes = JsonMapper.class)
@Requires(beans = JsonMapper.class)
@Internal
@Singleton
class DefaultAuthenticationMapper implements AuthenticationMapper {
    private final JsonMapper jsonMapper;
    private final TokenConfiguration tokenConfiguration;

    DefaultAuthenticationMapper(JsonMapper jsonMapper, TokenConfiguration tokenConfiguration) {
        this.jsonMapper = jsonMapper;
        this.tokenConfiguration = tokenConfiguration;
    }

    @Override
    public Authentication read(@NonNull String input) throws IOException {
        ClientAuthentication clientAuthentication = jsonMapper.readValue(input, Argument.of(ClientAuthentication.class));
        if (!clientAuthentication.getAttributes().containsKey("rolesKey")
            && !tokenConfiguration.getRolesName().equals(TokenConfiguration.DEFAULT_ROLES_NAME)) {
            Map<String, Object> attributes = new HashMap<>(clientAuthentication.getAttributes());
            attributes.put("rolesKey", tokenConfiguration.getRolesName());
            return new ClientAuthentication(clientAuthentication.getName(), attributes);
        }
        return clientAuthentication;
    }
}
