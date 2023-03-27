/*
 * Copyright 2017-2022 original authors
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
package io.micronaut.security.token.jwt.render;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.serde.annotation.Serdeable;

import jakarta.validation.constraints.NotBlank;
import java.util.Collection;

/**
 * Encapsulates an Access Token response as described in <a href="https://tools.ietf.org/html/rfc6749#section-4.1.4">RFC 6749</a>.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Serdeable
public class BearerAccessRefreshToken extends AccessRefreshToken {
    @NonNull
    @NotBlank
    private final String username;

    @Nullable
    private final Collection<String> roles;

    /**
     *
     * @param username a string e.g. admin
     * @param roles Collection of Strings e.g. ( [ROLE_USER, ROLE_ADMIN] )
     * @param expiresIn Access Token expiration
     * @param accessToken JWT token
     * @param refreshToken  JWT token
     * @param tokenType Type of token
     */
    public BearerAccessRefreshToken(@NonNull String username,
                                    @Nullable Collection<String> roles,
                                    @Nullable Integer expiresIn,
                                    @NonNull String accessToken,
                                    @Nullable String refreshToken,
                                    @NonNull String tokenType
    ) {
        super(accessToken, refreshToken, tokenType, expiresIn);
        this.username = username;
        this.roles = roles;
    }

    /**
     * username getter.
     * @return a string e.g. admin
     */
    @NonNull
    public String getUsername() {
        return username;
    }

    /**
     * roles getter.
     * @return Collection of Strings e.g. ( [ROLE_USER, ROLE_ADMIN] )
     */
    @Nullable
    public Collection<String> getRoles() {
        return roles;
    }
}
