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

import io.micronaut.core.annotation.Nullable;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.errors.OauthErrorResponseException;
import io.micronaut.security.errors.ObtainingAuthorizationErrorCode;
import io.micronaut.security.errors.PriorToLoginPersistence;
import io.micronaut.security.token.jwt.generator.AccessRefreshTokenGenerator;
import io.micronaut.security.token.jwt.generator.AccessTokenConfiguration;
import io.micronaut.security.token.jwt.render.AccessRefreshToken;
import jakarta.inject.Singleton;
import java.time.Duration;
import java.time.temporal.TemporalAmount;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Requires(property = SecurityConfigurationProperties.PREFIX + ".authentication", value = "cookie")
@Singleton
public class JwtCookieLoginHandler extends CookieLoginHandler {

    protected final AccessRefreshTokenGenerator accessRefreshTokenGenerator;
    protected final RefreshTokenCookieConfiguration refreshTokenCookieConfiguration;
    protected final AccessTokenConfiguration accessTokenConfiguration;

    /**
     * @param redirectConfiguration Redirect configuration
     * @param accessTokenCookieConfiguration JWT Access Token Cookie Configuration
     * @param refreshTokenCookieConfiguration Refresh Token Cookie Configuration
     * @param accessTokenConfiguration JWT Generator Configuration
     * @param accessRefreshTokenGenerator Access Refresh Token Generator
     * @param priorToLoginPersistence Prior To Login Persistence Mechanism
     */
    public JwtCookieLoginHandler(RedirectConfiguration redirectConfiguration,
                                 AccessTokenCookieConfiguration accessTokenCookieConfiguration,
                                 RefreshTokenCookieConfiguration refreshTokenCookieConfiguration,
                                 AccessTokenConfiguration accessTokenConfiguration,
                                 AccessRefreshTokenGenerator accessRefreshTokenGenerator,
                                 @Nullable PriorToLoginPersistence priorToLoginPersistence) {
        super(accessTokenCookieConfiguration, redirectConfiguration, priorToLoginPersistence);
        this.refreshTokenCookieConfiguration = refreshTokenCookieConfiguration;
        this.accessTokenConfiguration = accessTokenConfiguration;
        this.accessRefreshTokenGenerator = accessRefreshTokenGenerator;
    }

    @Override
    public List<Cookie> getCookies(UserDetails userDetails, HttpRequest<?> request) {
        AccessRefreshToken accessRefreshToken = accessRefreshTokenGenerator.generate(userDetails)
                .orElseThrow(() -> new OauthErrorResponseException(ObtainingAuthorizationErrorCode.SERVER_ERROR, "Cannot obtain an access token", null));

        return getCookies(accessRefreshToken, request);
    }

    @Override
    public List<Cookie> getCookies(UserDetails userDetails, String refreshToken, HttpRequest<?> request) {
        AccessRefreshToken accessRefreshToken = accessRefreshTokenGenerator.generate(refreshToken, userDetails)
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

        return cookies;
    }
}
