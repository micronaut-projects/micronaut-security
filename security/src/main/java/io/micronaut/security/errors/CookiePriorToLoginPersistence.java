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
package io.micronaut.security.errors;

import io.micronaut.context.annotation.Requires;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.cookie.CookieConfiguration;
import io.micronaut.security.config.RedirectConfigurationProperties;
import io.micronaut.security.config.TokenCookieConfiguration;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.Optional;

/**
 * Stores the last unauthorized URL in a cookie to redirect back to after
 * logging in.
 *
 * <p>Only the path and query of the original request are persisted, and only a
 * relative, same-origin URI is ever returned from {@link #getOriginalUri(HttpRequest, MutableHttpResponse)}.
 * A cookie value carrying a scheme or an authority (for example one injected from a
 * sibling sub-domain) is discarded so the post-login redirect cannot be turned into
 * an open redirect.</p>
 *
 * @author James Kleeh
 * @since 2.0.0
 */
@Requires(classes = HttpRequest.class)
@Requires(property = RedirectConfigurationProperties.PREFIX + ".prior-to-login", value = StringUtils.TRUE)
@Singleton
public class CookiePriorToLoginPersistence implements PriorToLoginPersistence<HttpRequest<?>, MutableHttpResponse<?>> {

    private static final Logger LOG = LoggerFactory.getLogger(CookiePriorToLoginPersistence.class);

    private static final String COOKIE_NAME = "ORIGINAL_URI";

    private final CookieConfiguration cookieConfiguration;

    public CookiePriorToLoginPersistence(@Nullable TokenCookieConfiguration cookieConfiguration) {
        this.cookieConfiguration = cookieConfiguration;
    }

    @Override
    public void onUnauthorized(HttpRequest<?> request, MutableHttpResponse<?> response) {
        Cookie cookie = Cookie.of(COOKIE_NAME, pathAndQuery(request.getUri()));
        configure(cookie, request);
        cookie.maxAge(Duration.ofMinutes(5));
        response.cookie(cookie);
    }

    @Override
    public Optional<URI> getOriginalUri(HttpRequest<?> request, MutableHttpResponse<?> response) {
        Optional<String> value = request.getCookies().get(COOKIE_NAME, String.class);
        if (value.isEmpty()) {
            return Optional.empty();
        }
        Cookie cookie = Cookie.of(COOKIE_NAME, "");
        configure(cookie, request);
        cookie.maxAge(0);
        response.cookie(cookie);
        return parseRelativeUri(value.get());
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

    /**
     * @param uri The request URI
     * @return The raw path and query of the URI, never its scheme or authority
     */
    @NonNull
    private static String pathAndQuery(@NonNull URI uri) {
        String path = uri.getRawPath();
        StringBuilder sb = new StringBuilder(StringUtils.isEmpty(path) ? "/" : path);
        String query = uri.getRawQuery();
        if (query != null) {
            sb.append('?').append(query);
        }
        return sb.toString();
    }

    /**
     * @param value The cookie value
     * @return The value parsed as a relative URI, or empty if the value is absolute, protocol-relative or malformed
     */
    @NonNull
    private static Optional<URI> parseRelativeUri(@NonNull String value) {
        if (StringUtils.isEmpty(value) || value.startsWith("//") || value.startsWith("\\")) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Ignoring {} cookie value \"{}\": not a relative URI", COOKIE_NAME, value);
            }
            return Optional.empty();
        }
        try {
            URI uri = new URI(value);
            if (uri.getScheme() != null || uri.getRawAuthority() != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Ignoring {} cookie value \"{}\": absolute URIs are not allowed", COOKIE_NAME, value);
                }
                return Optional.empty();
            }
            return Optional.of(uri);
        } catch (URISyntaxException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Ignoring {} cookie value \"{}\": {}", COOKIE_NAME, value, e.getMessage());
            }
            return Optional.empty();
        }
    }
}
