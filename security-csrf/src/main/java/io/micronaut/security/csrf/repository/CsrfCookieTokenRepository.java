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
package io.micronaut.security.csrf.repository;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.csrf.CsrfConfiguration;
import jakarta.inject.Singleton;
import java.util.Optional;

/**
 * Implementation of {@link CsrfTokenRepository}, which retrieves a CSRF token from a cookie value.
 * It is used within a Double-Submit Cookie Pattern.
 *
 * @author Sergio del Amo
 * @since 4.11.0
 */
@Singleton
public class CsrfCookieTokenRepository implements CsrfTokenRepository<HttpRequest<?>> {
    private final CsrfConfiguration csrfConfiguration;

    public CsrfCookieTokenRepository(CsrfConfiguration csrfConfiguration) {
        this.csrfConfiguration = csrfConfiguration;
    }

    @Override
    public Optional<String> findCsrfToken(HttpRequest<?> request) {
        return request.getCookies()
                .findCookie(csrfConfiguration.getCookieName())
                .map(Cookie::getValue);
    }
}
