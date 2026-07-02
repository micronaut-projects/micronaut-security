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

import io.micronaut.core.annotation.Internal;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.ProfileClaims;
import io.micronaut.security.token.RolesFinder;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.HashMap;
import java.util.Map;

/**
 * Base {@link AuthenticationMapper} implementation that maps token claims to an
 * {@link Authentication}.
 */
@Internal
public abstract class AbstractAuthenticationMapper implements AuthenticationMapper {

    private final RolesFinder rolesFinder;

    /**
     * Creates an authentication mapper.
     *
     * @param rolesFinder The roles finder used to resolve roles from claims
     */
    protected AbstractAuthenticationMapper(RolesFinder rolesFinder) {
        this.rolesFinder = rolesFinder;
    }

    /**
     * Creates an authentication from claims when a subject claim is present.
     *
     * @param claims The token claims
     * @return The authentication, or {@code null} if the claims do not contain a subject
     */
    protected @Nullable Authentication of(@NonNull Claims claims) {
        Object usernameObject = claims.get(Claims.SUBJECT);
        if (usernameObject == null) {
            return null;
        }
        return Authentication.build(
            usernameObject.toString(),
            rolesFinder.resolveRoles(claims.toMap()),
            attributes(claims)
        );
    }

    private static @NonNull Map<String, Object> attributes(@NonNull Claims claims) {
        Map<String, Object> attributes = new HashMap<>();
        for (String claim : ProfileClaims.all()) {
            Object claimValue = claims.get(claim);
            if (claimValue != null) {
                attributes.put(claim, claimValue);
            }
        }
        return  attributes;
    }
}
