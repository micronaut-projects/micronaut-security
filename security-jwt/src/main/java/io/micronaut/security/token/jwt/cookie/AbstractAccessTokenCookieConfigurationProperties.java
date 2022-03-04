/*
 * Copyright 2017-2022 original authors
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

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.cookie.SameSite;

import java.time.Duration;
import java.time.temporal.TemporalAmount;
import java.util.Optional;

/**
 * Base class for cookie configuration properties classes.
 *
 * @author Álvaro Sánchez-Mariscal
 */
public abstract class AbstractAccessTokenCookieConfigurationProperties implements AccessTokenCookieConfiguration {

    /**
     * The default http only value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_HTTPONLY = true;

    /**
     * Default Cookie Path.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_COOKIEPATH = "/";

    /**
     * The default same-site setting for the JWT cookie.
     */
    @SuppressWarnings("WeakerAccess")
    public static final SameSite DEFAULT_COOKIESAMESITE = null;

    protected String cookieDomain;
    protected String cookiePath = DEFAULT_COOKIEPATH;
    protected Boolean cookieHttpOnly = DEFAULT_HTTPONLY;
    protected Boolean cookieSecure;
    protected Duration cookieMaxAge;
    protected SameSite cookieSameSite = DEFAULT_COOKIESAMESITE;
    protected boolean enabled;
    protected String cookieName;

    /**
     *
     * @return a boolean flag indicating whether the JwtCookieTokenReader should be enabled or not
     */
    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     *
     * @return a name for the cookie
     */
    @NonNull
    @Override
    public String getCookieName() {
        return this.cookieName;
    }

    /**
     *
     * @return the domain name of this Cookie
     */
    @Override
    public Optional<String> getCookieDomain() {
        return Optional.ofNullable(cookieDomain);
    }

    /**
     *
     * @return The path of the cookie.
     */
    @Nullable
    @Override
    public Optional<String> getCookiePath() {
        return Optional.ofNullable(cookiePath);
    }

    /**
     * @return Whether the Cookie can only be accessed via HTTP.
     */
    @Override
    public Optional<Boolean> isCookieHttpOnly() {
        return Optional.ofNullable(cookieHttpOnly);
    }

    /**
     *
     * @return True if the cookie is secure
     */
    @Override
    public Optional<Boolean>  isCookieSecure() {
        return Optional.ofNullable(cookieSecure);
    }

    /**
     * @return The max age to use for the cookie
     */
    @Override
    public Optional<TemporalAmount> getCookieMaxAge() {
        return Optional.ofNullable(cookieMaxAge);
    }

    @Override
    public Optional<SameSite> getCookieSameSite() {
        return Optional.ofNullable(cookieSameSite);
    }

    /**
     * Sets the domain name of this Cookie.
     * @param cookieDomain the domain name of this Cookie
     */
    public void setCookieDomain(@Nullable String cookieDomain) {
        this.cookieDomain = cookieDomain;
    }

    /**
     * Sets the path of the cookie. Default value ({@value #DEFAULT_COOKIEPATH}).
     * @param cookiePath The path of the cookie.
     */
    public void setCookiePath(@Nullable String cookiePath) {
        this.cookiePath = cookiePath;
    }

    /**
     * Whether the Cookie can only be accessed via HTTP. Default value ({@value #DEFAULT_HTTPONLY}).
     * @param cookieHttpOnly Whether the Cookie can only be accessed via HTTP
     */
    public void setCookieHttpOnly(Boolean cookieHttpOnly) {
        this.cookieHttpOnly = cookieHttpOnly;
    }

    /**
     * Sets whether the cookie is secured. Defaults to the secure status of the request.
     * @param cookieSecure True if the cookie is secure
     */
    public void setCookieSecure(Boolean cookieSecure) {
        this.cookieSecure = cookieSecure;
    }

    /**
     * Sets the maximum age of the cookie.
     * @param cookieMaxAge The maximum age of the cookie
     */
    public void setCookieMaxAge(Duration cookieMaxAge) {
        this.cookieMaxAge = cookieMaxAge;
    }

    /**
     * Sets the same-site setting of the cookie. Default value null. Value is case sensitive. Allowed values: `Strict`, `Lax` or `None`.
     * @param cookieSameSite The same-site setting of the cookie.
     */
    public void setCookieSameSite(@Nullable SameSite cookieSameSite) {
        this.cookieSameSite = cookieSameSite;
    }

}
