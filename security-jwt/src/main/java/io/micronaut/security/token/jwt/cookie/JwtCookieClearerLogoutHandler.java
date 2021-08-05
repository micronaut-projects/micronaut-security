/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.token.jwt.cookie;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.cookie.CookieConfiguration;
import io.micronaut.security.authentication.CookieBasedAuthenticationModeCondition;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.handlers.LogoutHandler;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * Clears the cookie configured via {@link CookieLoginHandler}.
 * @author Sergio del Amo
 * @since 1.0
 */
@Requires(condition = CookieBasedAuthenticationModeCondition.class)
@Singleton
public class JwtCookieClearerLogoutHandler implements LogoutHandler {

    @Deprecated
    protected final JwtCookieConfiguration jwtCookieConfiguration;
    protected final String logout;
    protected final AccessTokenCookieConfiguration accessTokenCookieConfiguration;
    protected final RefreshTokenCookieConfiguration refreshTokenCookieConfiguration;

    /**
     * @param jwtCookieConfiguration JWT Cookie Configuration
     * @deprecated Use {@link JwtCookieClearerLogoutHandler#JwtCookieClearerLogoutHandler(AccessTokenCookieConfiguration, RefreshTokenCookieConfiguration, RedirectConfiguration)} instead.
     */
    @Deprecated
    public JwtCookieClearerLogoutHandler(JwtCookieConfiguration jwtCookieConfiguration) {
        this.jwtCookieConfiguration = jwtCookieConfiguration;
        this.accessTokenCookieConfiguration = jwtCookieConfiguration;
        this.refreshTokenCookieConfiguration = null;
        this.logout = jwtCookieConfiguration.getLogoutTargetUrl();
    }

    /**
     * @param jwtCookieConfiguration JWT Cookie Configuration
     * @param redirectConfiguration Redirect configuration
     * @deprecated Use {@link JwtCookieClearerLogoutHandler#JwtCookieClearerLogoutHandler(AccessTokenCookieConfiguration, RefreshTokenCookieConfiguration, RedirectConfiguration)} instead.
     */
    @Deprecated
    public JwtCookieClearerLogoutHandler(JwtCookieConfiguration jwtCookieConfiguration,
                                         RedirectConfiguration redirectConfiguration) {
        this.jwtCookieConfiguration = jwtCookieConfiguration;
        this.accessTokenCookieConfiguration = jwtCookieConfiguration;
        this.refreshTokenCookieConfiguration = null;
        this.logout = redirectConfiguration.getLogout();
    }

    /**
     * @param accessTokenCookieConfiguration JWT Cookie Configuration
     * @param refreshTokenCookieConfiguration Refresh token cookie configuration
     * @param redirectConfiguration Redirect configuration
     */
    @Inject
    public JwtCookieClearerLogoutHandler(AccessTokenCookieConfiguration accessTokenCookieConfiguration,
                                         RefreshTokenCookieConfiguration refreshTokenCookieConfiguration,
                                         RedirectConfiguration redirectConfiguration) {
        this.accessTokenCookieConfiguration = accessTokenCookieConfiguration;
        this.refreshTokenCookieConfiguration = refreshTokenCookieConfiguration;
        this.jwtCookieConfiguration = null;
        this.logout = redirectConfiguration.getLogout();
    }

    @Override
    public MutableHttpResponse<?> logout(HttpRequest<?> request) {
        try {
            URI location = new URI(logout);
            MutableHttpResponse<?> response = HttpResponse.seeOther(location);
            clearCookie(accessTokenCookieConfiguration, response);
            if (refreshTokenCookieConfiguration != null) {
                clearCookie(refreshTokenCookieConfiguration, response);
            }
            return response;
        } catch (URISyntaxException var5) {
            return HttpResponse.serverError();
        }
    }

    private void clearCookie(CookieConfiguration cookieConfiguration, MutableHttpResponse<?> response) {
        String domain = cookieConfiguration.getCookieDomain().orElse(null);
        String path = cookieConfiguration.getCookiePath().orElse(null);
        Cookie cookie = Cookie.of(cookieConfiguration.getCookieName(), "");
        cookie.maxAge(0).domain(domain).path(path);
        response.cookie(cookie);
    }
}
