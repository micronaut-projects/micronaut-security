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

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.cookie.CookieConfiguration;
import io.micronaut.security.config.RedirectConfigurationProperties;
import io.micronaut.security.config.TokenCookieConfiguration;
import jakarta.inject.Singleton;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.Optional;

/**
 * Stores the last unauthorized URL in a cookie to redirect back to after
 * logging in.
 *
 * <p>Only the path and query of the unauthorized request are persisted, and only a
 * local path (one that starts with a single {@code /}) is ever returned by
 * {@link #getOriginalUri(HttpRequest, MutableHttpResponse)}. A request line such as
 * {@code GET ///evil.example/x} or a planted cookie must not turn the post-login redirect
 * into a redirect to another host (CWE-601).</p>
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
        Optional<String> originalUri = localPathAndQuery(request.getUri());
        if (!originalUri.isPresent()) {
            return;
        }
        Cookie cookie = Cookie.of(COOKIE_NAME, originalUri.get());
        configure(cookie, request);
        cookie.maxAge(Duration.ofMinutes(5));
        response.cookie(cookie);
    }

    @Override
    public Optional<URI> getOriginalUri(HttpRequest<?> request, MutableHttpResponse<?> response) {
        Optional<Cookie> originalUriCookie = request.getCookies().findCookie(COOKIE_NAME);
        if (!originalUriCookie.isPresent()) {
            return Optional.empty();
        }
        Cookie expired = Cookie.of(COOKIE_NAME, "");
        configure(expired, request);
        expired.maxAge(0);
        response.cookie(expired);
        return parseUri(originalUriCookie.get().getValue()).filter(CookiePriorToLoginPersistence::isLocalUri);
    }

    @NonNull
    private static Optional<URI> parseUri(@Nullable String value) {
        if (value == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(new URI(value));
        } catch (URISyntaxException e) {
            return Optional.empty();
        }
    }

    /**
     * Extracts the path and query of a request URI when they denote a local path.
     *
     * @param uri The request URI
     * @return The raw path and query, or empty when the path is not a local path
     */
    @NonNull
    private static Optional<String> localPathAndQuery(@NonNull URI uri) {
        String path = uri.getRawPath();
        if (!isLocalPath(path)) {
            return Optional.empty();
        }
        String query = uri.getRawQuery();
        return Optional.of(query == null ? path : path + "?" + query);
    }

    /**
     * @param uri A URI
     * @return Whether the URI is a relative reference to a local path, that is, it has no scheme,
     * no authority and its path starts with a single {@code /}
     */
    private static boolean isLocalUri(@NonNull URI uri) {
        return uri.getScheme() == null
            && uri.getRawAuthority() == null
            && isLocalPath(uri.getRawPath())
            && isLocalPath(uri.toString());
    }

    /**
     * @param path A raw path
     * @return Whether the path starts with a single {@code /}. A path starting with {@code //} is rejected because
     * browsers interpret it as a scheme-relative URL pointing to another host.
     */
    private static boolean isLocalPath(@Nullable String path) {
        return path != null
            && path.startsWith("/")
            && !path.startsWith("//")
            && !path.startsWith("/\\");
    }

    /**
     * Configure the cookie.
     *
     * @param cookie The cookie
     * @param request The current request
     */
    protected void configure(Cookie cookie, HttpRequest<?> request) {
        if (cookieConfiguration != null) {
            cookie.configure(cookieConfiguration, request.isSecure());
        } else {
            cookie.secure(request.isSecure()).httpOnly(true);
            cookie.path("/");
        }
    }
}
