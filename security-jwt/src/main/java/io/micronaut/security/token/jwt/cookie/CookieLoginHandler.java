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
import io.micronaut.core.util.functional.ThrowingSupplier;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.config.RefreshRedirectConfiguration;
import io.micronaut.security.errors.PriorToLoginPersistence;
import io.micronaut.security.handlers.RedirectingLoginHandler;

import javax.inject.Inject;
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

    protected final JwtCookieConfiguration jwtCookieConfiguration;
    protected final PriorToLoginPersistence priorToLoginPersistence;
    protected final String loginFailure;
    protected final String loginSuccess;
    protected final String refresh;

    /**
     * @param redirectConfiguration Redirect configuration
     * @param jwtCookieConfiguration JWT Cookie Configuration
     * @param priorToLoginPersistence The prior to login persistence strategy
     */
    @Inject
    public CookieLoginHandler(JwtCookieConfiguration jwtCookieConfiguration,
                              RedirectConfiguration redirectConfiguration,
                              @Nullable PriorToLoginPersistence priorToLoginPersistence) {
        this.loginFailure = redirectConfiguration.getLoginFailure();
        this.loginSuccess = redirectConfiguration.getLoginSuccess();
        RefreshRedirectConfiguration refreshConfig = redirectConfiguration.getRefresh();
        this.refresh = refreshConfig.isEnabled() ? refreshConfig.getUrl() : null;
        this.jwtCookieConfiguration = jwtCookieConfiguration;
        this.priorToLoginPersistence = priorToLoginPersistence;
    }

    /**
     *
     * @param jwtCookieConfiguration JWT Cookie Configuration
     * @param loginSuccess Url to redirect to after a successful Login
     * @param loginFailure Url to redirect to after an unsuccessful login
     * @deprecated Use {@link CookieLoginHandler#CookieLoginHandler(JwtCookieConfiguration, RedirectConfiguration, PriorToLoginPersistence)} instead.
     */
    @Deprecated
    public CookieLoginHandler(JwtCookieConfiguration jwtCookieConfiguration,
                              String loginSuccess,
                              String loginFailure) {
        this.loginFailure = loginFailure;
        this.loginSuccess = loginSuccess;
        this.refresh = "/";
        this.jwtCookieConfiguration = jwtCookieConfiguration;
        this.priorToLoginPersistence = null;
    }

    protected abstract List<Cookie> getCookies(Authentication authentication, HttpRequest<?> request);

    protected abstract List<Cookie> getCookies(Authentication authentication, String refreshToken, HttpRequest<?> request);

    @Override
    public MutableHttpResponse<?> loginSuccess(Authentication authentication, HttpRequest<?> request) {
        return applyCookies(createSuccessResponse(request), getCookies(authentication, request));
    }

    @Override
    public MutableHttpResponse<?> loginFailed(AuthenticationResponse authenticationFailed, HttpRequest<?> request) {
        try {
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
     * @return A 303 HTTP Response
     */
    protected MutableHttpResponse<?> createSuccessResponse(HttpRequest<?> request) {
        try {
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
     * @return A 303 HTTP Response
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
