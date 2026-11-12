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

import io.micronaut.core.annotation.Experimental;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.Collection;
import java.util.Map;

/**
 * An {@link Authentication} that carries the access and refresh tokens an external authorization server
 * issued for the authenticated user.
 *
 * <p>Return an implementation from an authentication provider that delegates login to another service,
 * such as an identity provider that answers a password grant with its own tokens. Login handlers that would
 * otherwise mint tokens, such as {@link io.micronaut.security.token.cookie.TokenCookieLoginHandler} and
 * {@link io.micronaut.security.token.bearer.AccessRefreshTokenLoginHandler}, hand the carried tokens to the
 * client instead. The principal name, roles and attributes delegate to {@link #getAuthentication()}.</p>
 *
 * <p>The tokens are deliberately exposed through getters rather than {@link #getAttributes()}, so a handler
 * that does mint its own token never copies them into its claims.</p>
 *
 * @author Sergio del Amo
 * @since 5.6.0
 */
@Experimental
public interface AccessRefreshTokenAuthentication extends Authentication {

    /**
     * @return The access token issued by the authorization server, or {@code null} if it issued none
     */
    @Nullable
    String getAccessToken();

    /**
     * @return The refresh token issued by the authorization server, or {@code null} if it issued none
     */
    @Nullable
    String getRefreshToken();

    /**
     * @return Lifetime in seconds of the access token, or {@code null} if unknown
     */
    @Nullable
    default Integer getExpiresIn() {
        return null;
    }

    /**
     * @return The authentication the principal name, roles and attributes delegate to
     */
    @NonNull
    Authentication getAuthentication();

    @Override
    @NonNull
    default Map<String, Object> getAttributes() {
        return getAuthentication().getAttributes();
    }

    @Override
    @NonNull
    default Collection<String> getRoles() {
        return getAuthentication().getRoles();
    }

    @Override
    default String getName() {
        return getAuthentication().getName();
    }
}
