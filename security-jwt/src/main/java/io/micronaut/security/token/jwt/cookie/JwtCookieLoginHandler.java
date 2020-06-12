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

import edu.umd.cs.findbugs.annotations.Nullable;
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

import javax.inject.Inject;
import javax.inject.Singleton;
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
    protected final AccessTokenConfiguration accessTokenConfiguration;

    /**
     * @param jwtCookieConfiguration JWT Cookie Configuration
     * @param accessTokenConfiguration JWT Generator Configuration
     * @param accessRefreshTokenGenerator Access Refresh Token Generator
     * @deprecated Use {@link JwtCookieLoginHandler(RedirectConfiguration, JwtCookieConfiguration, AccessTokenConfiguration, AccessRefreshTokenGenerator,PriorToLoginPersistence)} instead.
     */
    @Deprecated
    public JwtCookieLoginHandler(JwtCookieConfiguration jwtCookieConfiguration,
                                 AccessTokenConfiguration accessTokenConfiguration,
                                 AccessRefreshTokenGenerator accessRefreshTokenGenerator) {
        super(jwtCookieConfiguration, jwtCookieConfiguration.getLoginSuccessTargetUrl(), jwtCookieConfiguration.getCookieName());
        this.accessTokenConfiguration = accessTokenConfiguration;
        this.accessRefreshTokenGenerator = accessRefreshTokenGenerator;
    }

    /**
     * @param redirectConfiguration Redirect configuration
     * @param jwtCookieConfiguration JWT Cookie Configuration
     * @param accessTokenConfiguration JWT Generator Configuration
     * @param accessRefreshTokenGenerator Access Refresh Token Generator
     * @param priorToLoginPersistence Prior To Login Persistence Mechanism
     */
    @Inject
    public JwtCookieLoginHandler(RedirectConfiguration redirectConfiguration,
                                 JwtCookieConfiguration jwtCookieConfiguration,
                                 AccessTokenConfiguration accessTokenConfiguration,
                                 AccessRefreshTokenGenerator accessRefreshTokenGenerator,
                                 @Nullable PriorToLoginPersistence priorToLoginPersistence) {
        super(jwtCookieConfiguration, redirectConfiguration, priorToLoginPersistence);
        this.accessTokenConfiguration = accessTokenConfiguration;
        this.accessRefreshTokenGenerator = accessRefreshTokenGenerator;
    }

    @Override
    protected List<Cookie> getCookies(UserDetails userDetails, HttpRequest<?> request) {
        AccessRefreshToken accessRefreshToken = accessRefreshTokenGenerator.generate(userDetails)
                .orElseThrow(() -> new OauthErrorResponseException(ObtainingAuthorizationErrorCode.SERVER_ERROR, "Cannot obtain an access token", null));

        return getCookies(accessRefreshToken, request);
    }

    @Override
    protected List<Cookie> getCookies(UserDetails userDetails, String refreshToken, HttpRequest<?> request) {
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

        Cookie jwtCookie = Cookie.of(jwtCookieConfiguration.getCookieName(), accessRefreshToken.getAccessToken());
        jwtCookie.configure(jwtCookieConfiguration, request.isSecure());
        TemporalAmount maxAge = jwtCookieConfiguration.getCookieMaxAge().orElseGet(() -> Duration.ofSeconds(accessTokenConfiguration.getExpiration()));
        jwtCookie.maxAge(maxAge);

        cookies.add(jwtCookie);

        String refreshToken = accessRefreshToken.getRefreshToken();
        if (StringUtils.isNotEmpty(refreshToken)) {
            Cookie refreshCookie = Cookie.of("JWT_REFRESH_TOKEN", refreshToken);
            refreshCookie.configure(jwtCookieConfiguration, request.isSecure());
            refreshCookie.maxAge(maxAge);
            cookies.add(refreshCookie);
        }

        return cookies;
    }
}
