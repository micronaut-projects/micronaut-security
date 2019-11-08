/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.bearer;

import javax.inject.Singleton;
import java.util.*;

import static io.micronaut.security.oauth2.bearer.IntrospectedToken.createActiveAuthentication;
import static io.micronaut.security.oauth2.bearer.IntrospectedToken.createInactiveAuthentication;

/**
 * Implements token introspection handling defined in <a href="https://tools.ietf.org/html/rfc7662">rfc7662</a>.
 * <p>
 * Token considered active if the introspection response has <code>"active"="true"</code> parameter
 */
@Singleton
public class DefaultTokenIntrospectionHandler implements TokenIntrospectionHandler {

    @Override
    public IntrospectedToken handle(Map<String, Object> tokenIntrospection) {
        boolean isActive = (Boolean) tokenIntrospection.get("active");
        List<String> roles = Optional.ofNullable(tokenIntrospection.get("scope"))
                .map(scopes -> ((String) scopes).trim().split("\\s+"))
                .map(Arrays::asList)
                .orElse(Collections.emptyList());
        String username = Objects.toString(tokenIntrospection.get("username"), "unknown");
        Integer issuingTimestamp = Optional.ofNullable((Integer) tokenIntrospection.get("iat")).orElse(0);
        Integer expirationTimestamp = Optional.ofNullable((Integer) tokenIntrospection.get("exp")).orElse(0);

        return isActive
                ? createActiveAuthentication(username, roles, issuingTimestamp, expirationTimestamp, tokenIntrospection)
                : createInactiveAuthentication();
    }
}
