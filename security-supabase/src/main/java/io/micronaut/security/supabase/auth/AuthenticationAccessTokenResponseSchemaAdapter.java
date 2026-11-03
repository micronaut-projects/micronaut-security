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
package io.micronaut.security.supabase.auth;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.security.authentication.AccessRefreshTokenAuthentication;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.supabase.auth.AccessTokenResponseSchema;
import io.micronaut.supabase.auth.UserSchema;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Adapts a Supabase Auth token response to an {@link AccessRefreshTokenAuthentication}.
 *
 * <p>The tokens Supabase issued are exposed through {@link #getAccessToken()}, {@link #getRefreshToken()} and
 * {@link #getExpiresIn()}, so cookie and bearer login handlers hand them to the client instead of minting their
 * own. Principal name, roles and attributes come from the embedded user through
 * {@link AuthenticationUserSchemaAdapter}.</p>
 *
 * @since 0.0.1
 */
@Experimental
public class AuthenticationAccessTokenResponseSchemaAdapter implements AccessRefreshTokenAuthentication {
    /**
     * Adapted token response.
     */
    private final AccessTokenResponseSchema response;

    /**
     * Principal derived from the user embedded in the response.
     */
    private final Authentication authentication;

    /**
     * Creates the adapter.
     *
     * @param response Token response of a {@code POST /token} grant
     * @throws IllegalArgumentException if the response embeds no user or the user has no identifier, since an
     *                                  {@link Authentication} requires a principal name
     */
    public AuthenticationAccessTokenResponseSchemaAdapter(@NonNull AccessTokenResponseSchema response) {
        UserSchema user = response.user();
        if (user == null || user.id() == null) {
            throw new IllegalArgumentException("Supabase token response embeds no user with an identifier");
        }
        this.response = response;
        this.authentication = new AuthenticationUserSchemaAdapter(user);
    }

    /**
     * Returns the adapted token response, for callers that need typed access beyond the tokens.
     *
     * @return The adapted token response
     */
    @NonNull
    public AccessTokenResponseSchema getResponse() {
        return response;
    }

    @Override
    @Nullable
    public String getAccessToken() {
        return response.accessToken();
    }

    @Override
    @Nullable
    public String getRefreshToken() {
        return response.refreshToken();
    }

    @Override
    @Nullable
    public Integer getExpiresIn() {
        return response.expiresIn();
    }

    @Override
    @NonNull
    public Authentication getAuthentication() {
        return authentication;
    }
}
