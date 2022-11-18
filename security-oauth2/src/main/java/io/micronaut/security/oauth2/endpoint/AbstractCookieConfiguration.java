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
package io.micronaut.security.oauth2.endpoint;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.cookie.CookieConfiguration;

import java.time.Duration;
import java.time.temporal.TemporalAmount;
import java.util.Optional;

/**
 * Base configuration for {@link io.micronaut.http.cookie.CookieConfiguration} implementations.
 *
 * @author Álvaro Sánchez-Mariscal
 */
public abstract class AbstractCookieConfiguration implements CookieConfiguration {

    private static final boolean DEFAULT_HTTPONLY = true;
    private static final String DEFAULT_COOKIEPATH = "/";

    private static final Duration DEFAULT_MAX_AGE = Duration.ofMinutes(5);

    protected String cookieDomain;
    protected Boolean cookieSecure;

    protected String cookiePath = DEFAULT_COOKIEPATH;
    protected Boolean cookieHttpOnly = DEFAULT_HTTPONLY;
    protected Duration cookieMaxAge = DEFAULT_MAX_AGE;
    protected String cookieName = null;

    @Override
    public Optional<String> getCookieDomain() {
        return Optional.ofNullable(cookieDomain);
    }

    /**
     * Sets the domain name of this Cookie. Default value (null).
     *
     * @param cookieDomain the domain name of this Cookie
     */
    public void setCookieDomain(@Nullable String cookieDomain) {
        this.cookieDomain = cookieDomain;
    }

    @Override
    public Optional<Boolean>  isCookieSecure() {
        return Optional.ofNullable(cookieSecure);
    }

    /**
     * Sets whether the cookie is secured. Defaults to the secure status of the request.
     *
     * @param cookieSecure True if the cookie is secure
     */
    public void setCookieSecure(Boolean cookieSecure) {
        this.cookieSecure = cookieSecure;
    }

    @NonNull
    @Override
    public String getCookieName() {
        if (cookieName != null) {
            return this.cookieName;
        }
        return defaultCookieName();
    }

    /**
     * Cookie Name.
     *
     * @param cookieName Cookie name
     */
    public void setCookieName(@NonNull String cookieName) {
        this.cookieName = cookieName;
    }

    public abstract String defaultCookieName();

    @Override
    public Optional<String> getCookiePath() {
        return Optional.ofNullable(cookiePath);
    }

    /**
     * Sets the path of the cookie. Default value ({@value io.micronaut.security.oauth2.endpoint.AbstractCookieConfiguration#DEFAULT_COOKIEPATH}).
     *
     * @param cookiePath The path of the cookie.
     */
    public void setCookiePath(@Nullable String cookiePath) {
        this.cookiePath = cookiePath;
    }

    @Override
    public Optional<Boolean> isCookieHttpOnly() {
        return Optional.ofNullable(cookieHttpOnly);
    }

    /**
     * Whether the Cookie can only be accessed via HTTP. Default value ({@value io.micronaut.security.oauth2.endpoint.AbstractCookieConfiguration#DEFAULT_HTTPONLY}).
     *
     * @param cookieHttpOnly Whether the Cookie can only be accessed via HTTP
     */
    public void setCookieHttpOnly(Boolean cookieHttpOnly) {
        this.cookieHttpOnly = cookieHttpOnly;
    }

    @Override
    public Optional<TemporalAmount> getCookieMaxAge() {
        return Optional.ofNullable(cookieMaxAge);
    }

    /**
     * Sets the maximum age of the cookie. Default value (5 minutes).
     *
     * @param cookieMaxAge The maximum age of the cookie
     */
    public void setCookieMaxAge(Duration cookieMaxAge) {
        this.cookieMaxAge = cookieMaxAge;
    }

}
