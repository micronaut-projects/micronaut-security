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

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.csrf.CsrfConfiguration;
import jakarta.inject.Singleton;

import java.util.Optional;

/**
 * Retrieves a CSRF Token from a Cookie named {@link CsrfConfiguration#getCookieName()}, for example, in a Double Submit Cookie pattern.
 * @author Sergio del Amo
 * @since 4.11.0
 */
@Requires(classes = HttpRequest.class)
@Requires(property = CsrfConfiguration.PREFIX + ".repository.cookie.enabled", value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@Singleton
public class CookieCsrfTokenRepository implements CsrfTokenRepository<HttpRequest<?>>  {
    private final CsrfConfiguration csrfConfiguration;

    /**
     *
     * @param csrfConfiguration CSRF Configuration
     */
    public CookieCsrfTokenRepository(CsrfConfiguration csrfConfiguration) {
        this.csrfConfiguration = csrfConfiguration;
    }

    @Override
    @NonNull
    public Optional<String> findCsrfToken(@NonNull HttpRequest<?> request) {
        return request.getCookies()
                .findCookie(csrfConfiguration.getCookieName())
                .map(Cookie::getValue);
    }
}
