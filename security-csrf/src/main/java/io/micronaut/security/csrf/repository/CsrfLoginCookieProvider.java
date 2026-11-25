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
import org.jspecify.annotations.NonNull;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.authentication.Authentication;
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
        return csrfCookie(request, csrfTokenGenerator.generateCsrfToken(request));
    }

    /**
     * Provides a CSRF Cookie whose token is bound to the authenticated user who is logging in. The cookie is built by
     * {@link #provideCookie(HttpRequest)}, so that subclasses overriding it to customize the cookie name, path or
     * attributes keep working, and its value is replaced with a token bound to the authenticated user.
     * @param request Request
     * @param authentication The authenticated user's representation
     * @return A CSRF Cookie
     * @since 5.5.2
     */
    @Override
    @NonNull
    public Cookie provideCookie(@NonNull HttpRequest<?> request, @NonNull Authentication authentication) {
        return provideCookie(request).value(csrfTokenGenerator.generateCsrfToken(request, authentication));
    }

    /**
     * Builds the CSRF cookie. Both {@link #provideCookie(HttpRequest)} and {@link #provideCookie(HttpRequest, Authentication)}
     * delegate to this method, so subclasses can override it to change the cookie name or attributes.
     * @param request Request
     * @param csrfToken The CSRF token
     * @return A CSRF Cookie
     * @since 5.5.2
     */
    @NonNull
    protected Cookie csrfCookie(@NonNull HttpRequest<?> request, @NonNull String csrfToken) {
        Cookie cookie = Cookie.of(csrfConfiguration.getCookieName(), csrfToken);
        cookie.configure(csrfConfiguration, request.isSecure());
        return cookie;
    }
}
