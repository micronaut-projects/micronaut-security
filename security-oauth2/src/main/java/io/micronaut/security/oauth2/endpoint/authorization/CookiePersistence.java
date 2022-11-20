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
package io.micronaut.security.oauth2.endpoint.authorization;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.cookie.CookieConfiguration;
import java.util.Optional;

/**
 * Utility Abstract class for Cookie Persistence.
 * @author Sergio del Amo
 * @since 3.9.0
 */
public abstract class CookiePersistence {

    protected final CookieConfiguration cookieConfiguration;

    /**
     *
     * @param cookieConfiguration Cookie Configuration
     */
    protected CookiePersistence(CookieConfiguration cookieConfiguration) {
        this.cookieConfiguration = cookieConfiguration;
    }

    /**
     *
     * @param request Request
     * @return The value of the cookie specified by {@link CookieConfiguration#getCookieName()}
     */
    protected Optional<String> retrieveValue(HttpRequest<?> request) {
        Cookie cookie = request.getCookies().get(cookieConfiguration.getCookieName());
        return Optional.ofNullable(cookie)
            .map(Cookie::getValue);
    }

    /**
     *
     * @param request HTTP Request
     * @param response HTTP Response
     * @param value Saves a cookie with name {@link CookieConfiguration#getCookieName()} with supplied value in the HTTP response.
     */
    protected void save(@NonNull HttpRequest<?> request,
                        @NonNull MutableHttpResponse<?> response,
                        @Nullable String value) {
        if (value != null) {
            Cookie cookie = Cookie.of(cookieConfiguration.getCookieName(), value);
            cookie.configure(cookieConfiguration, request.isSecure());
            response.cookie(cookie);
        }
    }

}
