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
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.handlers.LoginHandler;
import io.micronaut.security.token.jwt.generator.AccessRefreshTokenGenerator;
import io.micronaut.security.token.jwt.generator.AccessTokenConfiguration;
import io.micronaut.security.token.jwt.render.AccessRefreshToken;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.temporal.TemporalAmount;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Requires(property = SecurityConfigurationProperties.PREFIX + ".authentication", value = "cookie")
@Singleton
public class JwtCookieLoginHandler implements LoginHandler {

    protected final JwtCookieConfiguration jwtCookieConfiguration;
    protected final AccessRefreshTokenGenerator accessRefreshTokenGenerator;
    protected final AccessTokenConfiguration accessTokenConfiguration;
    protected final String loginFailure;
    protected final String loginSuccess;

    /**
     * @param jwtCookieConfiguration JWT Cookie Configuration
     * @param accessTokenConfiguration JWT Generator Configuration
     * @param accessRefreshTokenGenerator Access Refresh Token Generator
     * @deprecated Use {@link JwtCookieLoginHandler(RedirectConfiguration, JwtCookieConfiguration, AccessTokenConfiguration, AccessRefreshTokenGenerator)} instead.
     */
    @Deprecated
    public JwtCookieLoginHandler(JwtCookieConfiguration jwtCookieConfiguration,
                                 AccessTokenConfiguration accessTokenConfiguration,
                                 AccessRefreshTokenGenerator accessRefreshTokenGenerator) {
        this.jwtCookieConfiguration = jwtCookieConfiguration;
        this.accessTokenConfiguration = accessTokenConfiguration;
        this.accessRefreshTokenGenerator = accessRefreshTokenGenerator;
        this.loginFailure = jwtCookieConfiguration.getLoginFailureTargetUrl();
        this.loginSuccess = jwtCookieConfiguration.getLoginSuccessTargetUrl();
    }

    /**
     * @param redirectConfiguration Redirect configuration
     * @param jwtCookieConfiguration JWT Cookie Configuration
     * @param accessTokenConfiguration JWT Generator Configuration
     * @param accessRefreshTokenGenerator Access Refresh Token Generator
     */
    @Inject
    public JwtCookieLoginHandler(RedirectConfiguration redirectConfiguration,
            JwtCookieConfiguration jwtCookieConfiguration,
            AccessTokenConfiguration accessTokenConfiguration,
            AccessRefreshTokenGenerator accessRefreshTokenGenerator) {
        this.loginFailure = redirectConfiguration.getLoginFailure();
        this.loginSuccess = redirectConfiguration.getLoginSuccess();
        this.jwtCookieConfiguration = jwtCookieConfiguration;
        this.accessTokenConfiguration = accessTokenConfiguration;
        this.accessRefreshTokenGenerator = accessRefreshTokenGenerator;
    }

    @Override
    public MutableHttpResponse<?> loginSuccess(UserDetails userDetails, HttpRequest<?> request) {
        Optional<Cookie> cookieOptional = accessTokenCookie(userDetails, request);
        if (!cookieOptional.isPresent()) {
            return HttpResponse.serverError();
        }
        Cookie cookie = cookieOptional.get();
        return loginSuccessWithCookies(Arrays.asList(cookie));       
    }

    @Override
    public MutableHttpResponse<?> loginFailed(AuthenticationResponse authenticationFailed) {
        try {
            URI location = new URI(loginFailure);
            return HttpResponse.seeOther(location);
        } catch (URISyntaxException e) {
            return HttpResponse.serverError();
        }
    }
    
    /**
     *
     * @param userDetails Authenticated user's representation.
     * @param request The {@link HttpRequest} being executed
     * @return A Cookie containing the JWT or an empty optional.
     */
    protected Optional<Cookie> accessTokenCookie(UserDetails userDetails, HttpRequest<?> request) {
        Optional<AccessRefreshToken> accessRefreshTokenOptional = accessRefreshTokenGenerator.generate(userDetails);
        if (accessRefreshTokenOptional.isPresent()) {

            Cookie cookie = Cookie.of(jwtCookieConfiguration.getCookieName(), accessRefreshTokenOptional.get().getAccessToken());
            cookie.configure(jwtCookieConfiguration, request.isSecure());
            Optional<TemporalAmount> cookieMaxAge = jwtCookieConfiguration.getCookieMaxAge();
            if (cookieMaxAge.isPresent()) {
                cookie.maxAge(cookieMaxAge.get());
            } else {
                cookie.maxAge(Duration.ofSeconds(accessTokenConfiguration.getExpiration()));
            }
            return Optional.of(cookie);
        }
        return Optional.empty();
    }

    /**
     *
     * @param cookies Cookies to be added to the response
     * @return A 303 HTTP Response with cookies
     */
    protected MutableHttpResponse<?> loginSuccessWithCookies(List<Cookie> cookies) {
        try {
            URI location = new URI(loginSuccess);
            MutableHttpResponse<?> mutableHttpResponse = HttpResponse.seeOther(location);
            for (Cookie cookie : cookies) {
                mutableHttpResponse = mutableHttpResponse.cookie(cookie);
            }
            return mutableHttpResponse;
        } catch (URISyntaxException e) {
            return HttpResponse.serverError();
        }
    }
}

