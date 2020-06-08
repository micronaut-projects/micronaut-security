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
package io.micronaut.security.errors;

import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.cookie.CookieConfiguration;
import io.micronaut.security.config.RedirectConfigurationProperties;
import io.micronaut.security.config.TokenCookieConfiguration;

import javax.inject.Singleton;
import java.net.URI;
import java.time.Duration;
import java.util.Optional;

/**
 * Stores the last unauthorized URL in a cookie to redirect back to after
 * logging in.
 *
 * @author James Kleeh
 * @since 2.0.0
 */
@Requires(property = RedirectConfigurationProperties.PREFIX + ".prior-to-login", value = StringUtils.TRUE)
@Singleton
public class CookiePriorToLoginPersistence implements PriorToLoginPersistence {

    private static final String COOKIE_NAME = "ORIGINAL_URI";

    private final CookieConfiguration cookieConfiguration;

    public CookiePriorToLoginPersistence(@Nullable TokenCookieConfiguration cookieConfiguration) {
        this.cookieConfiguration = cookieConfiguration;
    }

    @Override
    public void onUnauthorized(HttpRequest<?> request, MutableHttpResponse<?> response) {
        Cookie cookie = Cookie.of(COOKIE_NAME, request.getUri().toString());
        configure(cookie, request);
        cookie.maxAge(Duration.ofMinutes(5));
        response.cookie(cookie);
    }

    @Override
    public Optional<URI> getOriginalUri(HttpRequest<?> request, MutableHttpResponse<?> response) {
        Optional<URI> uri = request.getCookies().get(COOKIE_NAME, URI.class);
        if (uri.isPresent()) {
            Cookie cookie = Cookie.of(COOKIE_NAME, "");
            configure(cookie, request);
            cookie.maxAge(0);
            response.cookie(cookie);
        }
        return uri;
    }

    /**
     * Configure the cookie
     *
     * @param cookie The cookie
     * @param request The current request
     */
    protected void configure(Cookie cookie, HttpRequest<?> request) {
        if (cookieConfiguration != null) {
            cookie.configure(cookieConfiguration, request.isSecure());
        } else {
            cookie.secure(request.isSecure()).httpOnly(true);
        }
    }
}
