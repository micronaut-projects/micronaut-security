/*
 * Copyright 2017-2020 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.endpoint.nonce.persistence.cookie;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.http.cookie.CookieConfiguration;
import io.micronaut.security.oauth2.endpoint.nonce.DefaultNonceConfiguration;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.time.Duration;
import java.util.Optional;

/**
 * @author James Kleeh
 * @since 1.2.0
 */
@ConfigurationProperties(CookieNoncePersistenceConfiguration.PREFIX)
public class CookieNoncePersistenceConfiguration implements CookieConfiguration {

    public static final String PREFIX = DefaultNonceConfiguration.PREFIX + ".cookie";

    private static final boolean DEFAULT_SECURE = true;
    private static final boolean DEFAULT_HTTPONLY = true;
    private static final String DEFAULT_COOKIENAME = "OPENID_NONCE";
    private static final String DEFAULT_COOKIEPATH = "/";
    private static final Duration DEFAULT_MAX_AGE = Duration.ofMinutes(5);

    private String cookieDomain;
    private String cookiePath = DEFAULT_COOKIEPATH;
    private Boolean cookieHttpOnly = DEFAULT_HTTPONLY;
    private Boolean cookieSecure = DEFAULT_SECURE;
    private Duration cookieMaxAge = DEFAULT_MAX_AGE;
    private String cookieName = DEFAULT_COOKIENAME;

    @Nonnull
    @Override
    public String getCookieName() {
        return this.cookieName;
    }

    /**
     * Cookie Name. Default value ({@value #DEFAULT_COOKIENAME}).
     *
     * @param cookieName Cookie name
     */
    public void setCookieName(@Nonnull String cookieName) {
        this.cookieName = cookieName;
    }

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
    public Optional<String> getCookiePath() {
        return Optional.ofNullable(cookiePath);
    }

    /**
     * Sets the path of the cookie. Default value ({@value #DEFAULT_COOKIEPATH}).
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
     * Whether the Cookie can only be accessed via HTTP. Default value ({@value #DEFAULT_HTTPONLY}).
     *
     * @param cookieHttpOnly Whether the Cookie can only be accessed via HTTP
     */
    public void setCookieHttpOnly(Boolean cookieHttpOnly) {
        this.cookieHttpOnly = cookieHttpOnly;
    }

    @Override
    public Optional<Boolean>  isCookieSecure() {
        return Optional.ofNullable(cookieSecure);
    }

    /**
     * Sets whether the cookie is secured. Default value ({@value #DEFAULT_SECURE}).
     *
     * @param cookieSecure True if the cookie is secure
     */
    public void setCookieSecure(Boolean cookieSecure) {
        this.cookieSecure = cookieSecure;
    }

    @Override
    public Optional<Duration> getCookieMaxAge() {
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
