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
import io.micronaut.core.util.functional.ThrowingSupplier;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.config.DefaultRedirectService;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.config.RedirectService;
import io.micronaut.security.config.RefreshRedirectConfiguration;
import io.micronaut.security.errors.PriorToLoginPersistence;
import io.micronaut.security.handlers.RedirectingLoginHandler;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;

/**
 * Abstract class which defines an implementation of {@link RedirectingLoginHandler} where a redirect response is issued.
 * For a successful login a cookie is added to the response with a token.
 *
 * @author Sergio del Amo
 * @since 2.0.0
 */
public abstract class CookieLoginHandler implements RedirectingLoginHandler {

    protected final AccessTokenCookieConfiguration accessTokenCookieConfiguration;
    protected final PriorToLoginPersistence priorToLoginPersistence;
    @Nullable
    protected final String loginFailure;

    @Nullable
    protected final String loginSuccess;

    @Nullable
    protected final String refresh;

    /**
     * @param accessTokenCookieConfiguration Access token cookie configuration
     * @param redirectConfiguration Redirect configuration
     * @param priorToLoginPersistence The prior to login persistence strategy
     * @deprecated Use {@link CookieLoginHandler(AccessTokenCookieConfiguration,RedirectConfiguration, RedirectService ,PriorToLoginPersistence)} instead.
     */
    @Deprecated
    public CookieLoginHandler(AccessTokenCookieConfiguration accessTokenCookieConfiguration,
                              RedirectConfiguration redirectConfiguration,
                              @Nullable PriorToLoginPersistence priorToLoginPersistence) {
        this(accessTokenCookieConfiguration, redirectConfiguration, new DefaultRedirectService(redirectConfiguration, () -> null), priorToLoginPersistence);
    }

    /**
     * @param accessTokenCookieConfiguration Access token cookie configuration
     * @param redirectConfiguration Redirect configuration
     * @param redirectService Redirect service
     * @param priorToLoginPersistence The prior to login persistence strategy
     */
    protected CookieLoginHandler(AccessTokenCookieConfiguration accessTokenCookieConfiguration,
                              RedirectConfiguration redirectConfiguration,
                              RedirectService redirectService,
                              @Nullable PriorToLoginPersistence priorToLoginPersistence) {
        this.loginFailure = redirectConfiguration.isEnabled() ? redirectService.loginFailureUrl() : null;
        this.loginSuccess = redirectConfiguration.isEnabled() ? redirectService.loginSuccessUrl() : null;
        RefreshRedirectConfiguration refreshConfig = redirectConfiguration.getRefresh();
        this.refresh = redirectConfiguration.isEnabled() && refreshConfig.isEnabled() ? redirectService.refreshUrl() : null;
        this.accessTokenCookieConfiguration = accessTokenCookieConfiguration;
        this.priorToLoginPersistence = priorToLoginPersistence;
    }

    /**
     * Return the cookies for the given parameters. This method will generate new cookies based on the current
     * configuration.
     *
     * @param authentication The Authenticated user's representation
     * @param request The current request
     * @return A list of cookies
     */
    public abstract List<Cookie> getCookies(Authentication authentication, HttpRequest<?> request);

    /**
     * Return the cookies for the given parameters. This method will generate new cookies based on the current
     * configuration.
     *
     * @param authentication The Authenticated user's representation
     * @param refreshToken The access refresh token
     * @param request The current request
     * @return A list of cookies
     */
    public abstract List<Cookie> getCookies(Authentication authentication, String refreshToken, HttpRequest<?> request);

    @Override
    public MutableHttpResponse<?> loginSuccess(Authentication authentication, HttpRequest<?> request) {
        return applyCookies(createSuccessResponse(request), getCookies(authentication, request));
    }

    /**
     * @param authenticationFailed Object encapsulates the Login failure
     * @param request The {@link HttpRequest} being executed
     * @return A 303 HTTP Response or 200 HTTP Response if {@link CookieLoginHandler#loginFailure} is null, for example if {@link RedirectConfiguration} is disabled.
     */
    @Override
    public MutableHttpResponse<?> loginFailed(AuthenticationResponse authenticationFailed, HttpRequest<?> request) {
        try {
            if (loginFailure == null) {
                return HttpResponse.ok();
            }
            URI location = new URI(loginFailure);
            return HttpResponse.seeOther(location);
        } catch (URISyntaxException e) {
            return HttpResponse.serverError();
        }
    }

    @Override
    public MutableHttpResponse<?> loginRefresh(Authentication authentication, String refreshToken, HttpRequest<?> request) {
        return applyCookies(createRefreshResponse(request), getCookies(authentication, refreshToken, request));
    }

    /**
     * @param request The request
     * @return A 303 HTTP Response or 200 HTTP Response if {@link CookieLoginHandler#loginSuccess} is null, for example if {@link RedirectConfiguration} is disabled.
     */
    protected MutableHttpResponse<?> createSuccessResponse(HttpRequest<?> request) {
        try {
            if (loginSuccess == null) {
                return HttpResponse.ok();
            }
            MutableHttpResponse<?> response = HttpResponse.status(HttpStatus.SEE_OTHER);
            ThrowingSupplier<URI, URISyntaxException> uriSupplier = () -> new URI(loginSuccess);
            if (priorToLoginPersistence != null) {
                Optional<URI> originalUri = priorToLoginPersistence.getOriginalUri(request, response);
                if (originalUri.isPresent()) {
                    uriSupplier = originalUri::get;
                }
            }
            response.getHeaders().location(uriSupplier.get());
            return response;
        } catch (URISyntaxException e) {
            return HttpResponse.serverError();
        }
    }

    /**
     * @param request The request
     * @return A 303 HTTP Response or 200 HTTP Response if {@link CookieLoginHandler#refresh} is null.
     */
    protected MutableHttpResponse<?> createRefreshResponse(HttpRequest<?> request) {
        try {
            if (refresh != null) {
                return HttpResponse.seeOther(new URI(refresh));
            } else {
                return HttpResponse.ok();
            }
        } catch (URISyntaxException e) {
            return HttpResponse.serverError();
        }
    }

    /**
     * @param response The response
     * @param cookies Cookies to be added to the response
     * @return A 303 HTTP Response with cookies
     */
    protected MutableHttpResponse<?> applyCookies(MutableHttpResponse<?> response, List<Cookie> cookies) {
        for (Cookie cookie : cookies) {
            response = response.cookie(cookie);
        }
        return response;
    }
}
