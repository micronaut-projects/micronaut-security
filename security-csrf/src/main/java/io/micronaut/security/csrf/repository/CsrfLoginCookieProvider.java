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
import io.micronaut.http.HttpRequest;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.csrf.CsrfConfiguration;
import io.micronaut.security.csrf.generator.CsrfTokenGenerator;
import io.micronaut.security.token.cookie.LoginCookieProvider;
import jakarta.inject.Singleton;

/**
 * Provides a CSRF Cookie which can be included in the login response.
 * @author Sergio del Amo
 * @since 4.11.0
 */
@Requires(classes = HttpRequest.class)
@Singleton
public class CsrfLoginCookieProvider implements LoginCookieProvider<HttpRequest<?>> {
    private final CsrfTokenGenerator<HttpRequest<?>> csrfTokenGenerator;
    private final CsrfConfiguration csrfConfiguration;

    /**
     *
     * @param csrfTokenGenerator CSRF Token Generator
     * @param csrfConfiguration CSRF Configuration
     */
    public CsrfLoginCookieProvider(CsrfTokenGenerator<HttpRequest<?>> csrfTokenGenerator,
                                   CsrfConfiguration csrfConfiguration) {
        this.csrfTokenGenerator = csrfTokenGenerator;
        this.csrfConfiguration = csrfConfiguration;
    }

    @Override
    @NonNull
    public Cookie provideCookie(@NonNull HttpRequest<?> request) {
        String csrfToken = csrfTokenGenerator.generateCsrfToken(request);
        Cookie cookie = Cookie.of(csrfConfiguration.getCookieName(), csrfToken);
        cookie.configure(csrfConfiguration, request.isSecure());
        return cookie;
    }
}
