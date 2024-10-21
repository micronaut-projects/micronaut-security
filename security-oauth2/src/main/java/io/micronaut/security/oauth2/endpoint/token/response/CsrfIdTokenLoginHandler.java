/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.oauth2.endpoint.token.response;

import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
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
import io.micronaut.security.token.cookie.CookieLoginHandler;
import jakarta.inject.Singleton;

import java.util.*;

/**
 * Sets {@link CookieLoginHandler}`s cookie value to the idtoken received from an authentication provider.
 * The cookie expiration is set to the expiration of the IDToken exp claim.
 *
 * @author Sergio del Amo
 * @since 2.0.0
 */
@Requires(property = SecurityConfigurationProperties.PREFIX + ".authentication", value = "idtoken")
@Requires(classes = HttpRequest.class)
@Requires(beans = { CsrfConfiguration.class, CsrfTokenGenerator.class })
@Replaces(IdTokenLoginHandler.class)
@Singleton
public class CsrfIdTokenLoginHandler extends IdTokenLoginHandler {
    private final CsrfTokenGenerator<HttpRequest<?>> csrfTokenGenerator;
    private final CsrfConfiguration csrfConfiguration;

    /**
     * @param accessTokenCookieConfiguration Access token cookie configuration
     * @param redirectConfiguration          Redirect configuration
     * @param redirectService                Redirect service
     * @param priorToLoginPersistence        The prior to login persistence strategy
     * @param csrfTokenGenerator CSRF Token Generator
     * @param csrfConfiguration CSRF Configuration
     */
    public CsrfIdTokenLoginHandler(AccessTokenCookieConfiguration accessTokenCookieConfiguration,
                                   RedirectConfiguration redirectConfiguration,
                                   RedirectService redirectService,
                                   @Nullable PriorToLoginPersistence<HttpRequest<?>, MutableHttpResponse<?>> priorToLoginPersistence,
                                   CsrfTokenGenerator<HttpRequest<?>> csrfTokenGenerator,
                                   CsrfConfiguration csrfConfiguration) {
        super(accessTokenCookieConfiguration, redirectConfiguration, redirectService, priorToLoginPersistence);
        this.csrfTokenGenerator = csrfTokenGenerator;
        this.csrfConfiguration = csrfConfiguration;
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
        String csrfToken = csrfTokenGenerator.generate(request);
        return csrfCookie(csrfToken, request);
    }

    @NonNull
    private Cookie csrfCookie(@NonNull String csrfToken, @NonNull HttpRequest<?> request) {
        Cookie cookie = Cookie.of(csrfConfiguration.getCookieName(), csrfToken);
        cookie.configure(csrfConfiguration, request.isSecure());
        return cookie;
    }
}
