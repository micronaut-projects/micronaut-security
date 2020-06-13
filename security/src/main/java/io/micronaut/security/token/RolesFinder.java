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

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.security.authentication.Authentication;

import java.util.List;
import java.util.Map;

/**
 * Retrieves roles from token claims.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
public interface RolesFinder {

    /**
     * Retrieves the list of roles from the provided claims.
     *
     * @param claims The claims of the token.
     * @return The granted roles.
     */
    @NonNull
    List<String> findInClaims(@NonNull Claims claims);

    /**
     * Retrieves the list of roles from the User Attributes.
     *
     * @param authentication User's authentication representation
     * @return The granted roles.
     */
    @NonNull
    List<String> resolveRoles(@NonNull Authentication authentication);

    /**
     * Retrieves the list of roles from the User Attributes.
     *
     * @param attributes User's attributes
     * @return The granted roles.
     */
    @NonNull
    List<String> resolveRoles(@Nullable Map<String, Object> attributes);

}
