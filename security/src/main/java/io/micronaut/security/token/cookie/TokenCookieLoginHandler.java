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
import io.micronaut.core.annotation.NonNull;
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
import io.micronaut.security.token.TokenAuthenticationNames;
import io.micronaut.security.token.config.TokenConfiguration;
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
import java.util.Optional;

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
    protected final List<LoginCookieProvider<HttpRequest<?>>> loginCookieProviders;
    private TokenConfiguration tokenConfiguration = new TokenConfiguration() { };

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

    /**
     * Sets the Token Configuration used to name the authentication supplied to the {@link LoginCookieProvider} beans as
     * token based authentication names the user from the issued token. Injected by method rather than by constructor so
     * that subclasses using any constructor get the application's configuration. Defaults to the default
     * {@code micronaut.security.token.name-key}, {@code sub}.
     * @param tokenConfiguration Token Configuration
     * @since 4.18.2
     * @deprecated Method injection is used only to keep the existing constructors of this class and of its subclasses working.
     * This method will be removed in the next major release in favour of pure constructor injection, when the
     * {@code TokenConfiguration} becomes a constructor parameter. Subclasses should not rely on it.
     */
    @Deprecated(forRemoval = true, since = "4.18.2")
    @Inject
    public final void setTokenConfiguration(@NonNull TokenConfiguration tokenConfiguration) {
        this.tokenConfiguration = tokenConfiguration;
    }

    @Override
    public List<Cookie> getCookies(Authentication authentication, HttpRequest<?> request) {
        AccessRefreshToken accessRefreshToken = accessRefreshTokenGenerator.generate(authentication)
                .orElseThrow(() -> new OauthErrorResponseException(ObtainingAuthorizationErrorCode.SERVER_ERROR, "Cannot obtain an access token", null));

        return getCookies(authentication, accessRefreshToken, request);
    }

    @Override
    public List<Cookie> getCookies(Authentication authentication, String refreshToken, HttpRequest<?> request) {
        AccessRefreshToken accessRefreshToken = accessRefreshTokenGenerator.generate(refreshToken, authentication)
                .orElseThrow(() -> new OauthErrorResponseException(ObtainingAuthorizationErrorCode.SERVER_ERROR, "Cannot obtain an access token", null));

        return getCookies(authentication, accessRefreshToken, request);
    }

    /**
     * Return the cookies for the given parameters. The cookies supplied by the {@link LoginCookieProvider} beans
     * are generated for the authenticated user via {@link LoginCookieProvider#provideCookie(Object, Authentication)},
     * with the authentication named as token based authentication names the user from the issued token
     * (the {@code micronaut.security.token.name-key} claim, falling back to the principal name).
     * The cookies are obtained from {@link #getCookies(AccessRefreshToken, HttpRequest)}, so that subclasses overriding
     * it keep their customizations, and the values of the cookies supplied by the {@link LoginCookieProvider} beans are
     * then replaced with the ones generated for the authenticated user.
     *
     * @param authentication The Authenticated user's representation
     * @param accessRefreshToken The access refresh token
     * @param request The current request
     * @return A list of cookies
     * @since 4.18.2
     */
    @NonNull
    @SuppressWarnings("removal")
    protected List<Cookie> getCookies(@NonNull Authentication authentication,
                                      @NonNull AccessRefreshToken accessRefreshToken,
                                      @NonNull HttpRequest<?> request) {
        Authentication tokenAuthentication = TokenAuthenticationNames.asResolvedFromToken(tokenConfiguration, authentication);
        return bindLoginCookies(getCookies(accessRefreshToken, request), tokenAuthentication, request);
    }

    /**
     * Replaces the value of the cookies supplied by the {@link LoginCookieProvider} beans with the value generated for
     * the authenticated user. A cookie which is not present, for example because an override removed it, is not added.
     * @param cookies Cookies returned by {@link #getCookies(AccessRefreshToken, HttpRequest)}
     * @param authentication The authenticated user's representation
     * @param request The current request
     * @return The cookies bound to the authenticated user
     */
    @NonNull
    private List<Cookie> bindLoginCookies(@NonNull List<Cookie> cookies,
                                          @NonNull Authentication authentication,
                                          @NonNull HttpRequest<?> request) {
        for (LoginCookieProvider<HttpRequest<?>> loginCookieProvider : loginCookieProviders) {
            Cookie bound = loginCookieProvider.provideCookie(request, authentication);
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(bound.getName())) {
                    cookie.value(bound.getValue());
                }
            }
        }
        return cookies;
    }

    /**
     * Return the cookies for the given parameters.
     *
     * @param accessRefreshToken The access refresh token
     * @param request The current request
     * @return A list of cookies
     * @deprecated Override {@link #getCookies(Authentication, AccessRefreshToken, HttpRequest)} instead. This method is still invoked on login by {@link #getCookies(Authentication, AccessRefreshToken, HttpRequest)}, which then replaces the values of the cookies supplied by {@link LoginCookieProvider} beans with the ones bound to the authenticated user, so an override keeps its customizations; the cookies it supplies via {@link LoginCookieProvider#provideCookie(Object)} are not bound to the user by themselves.
     */
    @Deprecated(forRemoval = true, since = "4.18.2")
    protected List<Cookie> getCookies(AccessRefreshToken accessRefreshToken, HttpRequest<?> request) {
        List<Cookie> cookies = new ArrayList<>(2);
        cookies.add(accessTokenCookie(accessRefreshToken, request));
        refreshTokenCookie(accessRefreshToken, request).ifPresent(cookies::add);
        for (LoginCookieProvider<HttpRequest<?>> loginCookieProvider : loginCookieProviders) {
            cookies.add(loginCookieProvider.provideCookie(request));
        }
        return cookies;
    }

    /**
     * Instantiates an Access Token Cookie.
     * @param accessRefreshToken The access refresh token
     * @param request The current request
     * @return Access Token Cookie
     */
    @NonNull
    protected Cookie accessTokenCookie(@NonNull AccessRefreshToken accessRefreshToken, @NonNull HttpRequest<?> request) {
        Cookie jwtCookie = Cookie.of(accessTokenCookieConfiguration.getCookieName(), accessRefreshToken.getAccessToken());
        jwtCookie.configure(accessTokenCookieConfiguration, request.isSecure());
        if (!accessTokenCookieConfiguration.isSessionCookie()) {
            TemporalAmount maxAge = accessTokenCookieConfiguration.getCookieMaxAge().orElseGet(() -> Duration.ofSeconds(accessTokenConfiguration.getExpiration()));
            jwtCookie.maxAge(maxAge);
        }
        return jwtCookie;
    }

    /**
     * Instantiates a Refresh Token Cookie.
     * @param accessRefreshToken The access refresh token
     * @param request The current request
     * @return Refresh Token Cookie
     */
    @NonNull
    protected Optional<Cookie> refreshTokenCookie(@NonNull AccessRefreshToken accessRefreshToken,
                                                  @NonNull HttpRequest<?> request) {
        String refreshToken = accessRefreshToken.getRefreshToken();
        if (StringUtils.isEmpty(refreshToken)) {
            return Optional.empty();
        }
        Cookie refreshCookie = Cookie.of(refreshTokenCookieConfiguration.getCookieName(), refreshToken);
        refreshCookie.configure(refreshTokenCookieConfiguration, request.isSecure());
        if (!refreshTokenCookieConfiguration.isSessionCookie()) {
            refreshCookie.maxAge(refreshTokenCookieConfiguration.getCookieMaxAge().orElseGet(() -> Duration.ofDays(30)));
        }
        return Optional.of(refreshCookie);
    }
}
