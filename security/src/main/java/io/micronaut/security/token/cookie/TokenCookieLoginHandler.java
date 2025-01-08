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
package io.micronaut.security.token.cookie;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.config.RedirectService;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.errors.OauthErrorResponseException;
import io.micronaut.security.errors.ObtainingAuthorizationErrorCode;
import io.micronaut.security.errors.PriorToLoginPersistence;
import io.micronaut.security.token.generator.AccessRefreshTokenGenerator;
import io.micronaut.security.token.generator.AccessTokenConfiguration;
import io.micronaut.security.token.render.AccessRefreshToken;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.time.Duration;
import java.time.temporal.TemporalAmount;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Requires(classes = { HttpRequest.class })
@Requires(property = SecurityConfigurationProperties.PREFIX + ".authentication", value = "cookie")
@Singleton
public class TokenCookieLoginHandler extends CookieLoginHandler {

    protected final AccessRefreshTokenGenerator accessRefreshTokenGenerator;
    protected final RefreshTokenCookieConfiguration refreshTokenCookieConfiguration;
    protected final AccessTokenConfiguration accessTokenConfiguration;
    private final List<LoginCookieProvider<HttpRequest<?>>> loginCookieProviders;

    /**
     * @param redirectService Redirection Service
     * @param redirectConfiguration Redirect configuration
     * @param accessTokenCookieConfiguration JWT Access Token Cookie Configuration
     * @param refreshTokenCookieConfiguration Refresh Token Cookie Configuration
     * @param accessTokenConfiguration JWT Generator Configuration
     * @param accessRefreshTokenGenerator Access Refresh Token Generator
     * @param priorToLoginPersistence Prior To Login Persistence Mechanism
     * @param loginCookieProviders Login Cookie Providers
     */
    @Inject
    public TokenCookieLoginHandler(RedirectService redirectService,
                                   RedirectConfiguration redirectConfiguration,
                                   AccessTokenCookieConfiguration accessTokenCookieConfiguration,
                                   RefreshTokenCookieConfiguration refreshTokenCookieConfiguration,
                                   AccessTokenConfiguration accessTokenConfiguration,
                                   AccessRefreshTokenGenerator accessRefreshTokenGenerator,
                                   @Nullable PriorToLoginPersistence<HttpRequest<?>, MutableHttpResponse<?>> priorToLoginPersistence,
                                   List<LoginCookieProvider<HttpRequest<?>>> loginCookieProviders) {
        super(accessTokenCookieConfiguration, redirectConfiguration, redirectService, priorToLoginPersistence);
        this.refreshTokenCookieConfiguration = refreshTokenCookieConfiguration;
        this.accessTokenConfiguration = accessTokenConfiguration;
        this.accessRefreshTokenGenerator = accessRefreshTokenGenerator;
        this.loginCookieProviders = loginCookieProviders;
    }

    /**
     * @param redirectService Redirection Service
     * @param redirectConfiguration Redirect configuration
     * @param accessTokenCookieConfiguration JWT Access Token Cookie Configuration
     * @param refreshTokenCookieConfiguration Refresh Token Cookie Configuration
     * @param accessTokenConfiguration JWT Generator Configuration
     * @param accessRefreshTokenGenerator Access Refresh Token Generator
     * @param priorToLoginPersistence Prior To Login Persistence Mechanism
     * @deprecated Use {@link TokenCookieLoginHandler#TokenCookieLoginHandler(RedirectService, RedirectConfiguration, AccessTokenCookieConfiguration, RefreshTokenCookieConfiguration, AccessTokenConfiguration, AccessRefreshTokenGenerator, PriorToLoginPersistence, List)} instead.
     */
    @Deprecated(forRemoval = true, since = "4.11.0")
    public TokenCookieLoginHandler(RedirectService redirectService,
                                 RedirectConfiguration redirectConfiguration,
                                 AccessTokenCookieConfiguration accessTokenCookieConfiguration,
                                 RefreshTokenCookieConfiguration refreshTokenCookieConfiguration,
                                 AccessTokenConfiguration accessTokenConfiguration,
                                 AccessRefreshTokenGenerator accessRefreshTokenGenerator,
                                 @Nullable PriorToLoginPersistence<HttpRequest<?>, MutableHttpResponse<?>> priorToLoginPersistence) {
        this(redirectService, redirectConfiguration, accessTokenCookieConfiguration, refreshTokenCookieConfiguration, accessTokenConfiguration, accessRefreshTokenGenerator, priorToLoginPersistence, Collections.emptyList());
    }

    @Override
    public List<Cookie> getCookies(Authentication authentication, HttpRequest<?> request) {
        AccessRefreshToken accessRefreshToken = accessRefreshTokenGenerator.generate(authentication)
                .orElseThrow(() -> new OauthErrorResponseException(ObtainingAuthorizationErrorCode.SERVER_ERROR, "Cannot obtain an access token", null));

        return getCookies(accessRefreshToken, request);
    }

    @Override
    public List<Cookie> getCookies(Authentication authentication, String refreshToken, HttpRequest<?> request) {
        AccessRefreshToken accessRefreshToken = accessRefreshTokenGenerator.generate(refreshToken, authentication)
                .orElseThrow(() -> new OauthErrorResponseException(ObtainingAuthorizationErrorCode.SERVER_ERROR, "Cannot obtain an access token", null));

        return getCookies(accessRefreshToken, request);
    }

    /**
     * Return the cookies for the given parameters.
     *
     * @param accessRefreshToken The access refresh token
     * @param request The current request
     * @return A list of cookies
     */
    protected List<Cookie> getCookies(AccessRefreshToken accessRefreshToken, HttpRequest<?> request) {
        List<Cookie> cookies = new ArrayList<>(2);
        Cookie jwtCookie = Cookie.of(accessTokenCookieConfiguration.getCookieName(), accessRefreshToken.getAccessToken());
        jwtCookie.configure(accessTokenCookieConfiguration, request.isSecure());
        TemporalAmount maxAge = accessTokenCookieConfiguration.getCookieMaxAge().orElseGet(() -> Duration.ofSeconds(accessTokenConfiguration.getExpiration()));
        jwtCookie.maxAge(maxAge);

        cookies.add(jwtCookie);

        String refreshToken = accessRefreshToken.getRefreshToken();
        if (StringUtils.isNotEmpty(refreshToken)) {
            Cookie refreshCookie = Cookie.of(refreshTokenCookieConfiguration.getCookieName(), refreshToken);
            refreshCookie.configure(refreshTokenCookieConfiguration, request.isSecure());
            refreshCookie.maxAge(refreshTokenCookieConfiguration.getCookieMaxAge().orElseGet(() -> Duration.ofDays(30)));
            cookies.add(refreshCookie);
        }

        for (LoginCookieProvider<HttpRequest<?>> loginCookieProvider : loginCookieProviders) {
            cookies.add(loginCookieProvider.provideCookie(request));
        }
        return cookies;
    }
}
