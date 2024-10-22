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

import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.config.RedirectService;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.csrf.CsrfConfiguration;
import io.micronaut.security.csrf.generator.CsrfTokenGenerator;
import io.micronaut.security.errors.PriorToLoginPersistence;
import io.micronaut.security.token.cookie.AccessTokenCookieConfiguration;
import io.micronaut.security.token.cookie.RefreshTokenCookieConfiguration;
import io.micronaut.security.token.cookie.TokenCookieLoginHandler;
import io.micronaut.security.token.generator.AccessRefreshTokenGenerator;
import io.micronaut.security.token.generator.AccessTokenConfiguration;
import jakarta.inject.Singleton;

import java.util.List;

/**
 * Replaces {@link TokenCookieLoginHandler} to add an extra CSRF Cookie to the response.
 * @author Sergio del Amo
 * @since 4.11.0
 */
@Internal
@Requires(classes = { HttpRequest.class })
@Requires(property = SecurityConfigurationProperties.PREFIX + ".authentication", value = "cookie")
@Replaces(TokenCookieLoginHandler.class)
@Singleton
public class CrsrfTokenCookieLoginHandler extends TokenCookieLoginHandler {
    private final CsrfConfiguration csrfConfiguration;
    private final CsrfTokenGenerator<HttpRequest<?>> csrfTokenGenerator;

    /**
     * @param redirectService                 Redirection Service
     * @param redirectConfiguration           Redirect configuration
     * @param accessTokenCookieConfiguration  JWT Access Token Cookie Configuration
     * @param refreshTokenCookieConfiguration Refresh Token Cookie Configuration
     * @param accessTokenConfiguration        JWT Generator Configuration
     * @param accessRefreshTokenGenerator     Access Refresh Token Generator
     * @param priorToLoginPersistence         Prior To Login Persistence Mechanism
     * @param csrfConfiguration CSRF Configuration
     * @param csrfTokenGenerator CSRF Token Generator
     */
    public CrsrfTokenCookieLoginHandler(RedirectService redirectService,
                                        RedirectConfiguration redirectConfiguration,
                                        AccessTokenCookieConfiguration accessTokenCookieConfiguration,
                                        RefreshTokenCookieConfiguration refreshTokenCookieConfiguration,
                                        AccessTokenConfiguration accessTokenConfiguration,
                                        AccessRefreshTokenGenerator accessRefreshTokenGenerator,
                                        @Nullable PriorToLoginPersistence<HttpRequest<?>, MutableHttpResponse<?>> priorToLoginPersistence,
                                        CsrfConfiguration csrfConfiguration,
                                        CsrfTokenGenerator<HttpRequest<?>> csrfTokenGenerator) {
        super(redirectService, redirectConfiguration, accessTokenCookieConfiguration, refreshTokenCookieConfiguration, accessTokenConfiguration, accessRefreshTokenGenerator, priorToLoginPersistence);
        this.csrfConfiguration = csrfConfiguration;
        this.csrfTokenGenerator = csrfTokenGenerator;
    }

    @Override
    public List<Cookie> getCookies(Authentication authentication, HttpRequest<?> request) {
        List<Cookie> cookies =  super.getCookies(authentication, request);
        cookies.add(csrfCookie(request));
        return cookies;
    }

    @Override
    public List<Cookie> getCookies(Authentication authentication, String refreshToken, HttpRequest<?> request) {
        List<Cookie> cookies =  super.getCookies(authentication, refreshToken, request);
        cookies.add(csrfCookie(request));
        return cookies;
    }

    @NonNull
    private Cookie csrfCookie(@NonNull HttpRequest<?> request) {
        String csrfToken = csrfTokenGenerator.generateCsrfToken(request);
        return csrfCookie(csrfToken, request);
    }

    @NonNull
    private Cookie csrfCookie(@NonNull String csrfToken, @NonNull HttpRequest<?> request) {
        Cookie cookie = Cookie.of(csrfConfiguration.getCookieName(), csrfToken);
        cookie.configure(csrfConfiguration, request.isSecure());
        return cookie;
    }
}
