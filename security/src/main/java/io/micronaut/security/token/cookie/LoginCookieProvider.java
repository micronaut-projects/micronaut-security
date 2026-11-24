/*
 * Copyright 2017-2024 original authors
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
package io.micronaut.security.token.cookie;

import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.authentication.Authentication;
import org.jspecify.annotations.NonNull;

/**
 * Provides a Cookie which will be included in the login response.
 * @author Sergio del Amo
 * @since 4.11.0
 * @param <T> Request
 */
public interface LoginCookieProvider<T> {
    @NonNull
    Cookie provideCookie(@NonNull T request);

    /**
     * Provides a Cookie which will be included in the login response of the supplied authenticated user.
     * Implementations which issue a value that should be bound to the authenticated user, for example a signed CSRF token,
     * should override this method, as the login request itself does not carry the authentication yet.
     * The default implementation delegates to {@link #provideCookie(Object)}.
     * @param request Request
     * @param authentication The authenticated user's representation
     * @return A Cookie
     * @since 5.5.2
     */
    @NonNull
    default Cookie provideCookie(@NonNull T request, @NonNull Authentication authentication) {
        return provideCookie(request);
    }
}
