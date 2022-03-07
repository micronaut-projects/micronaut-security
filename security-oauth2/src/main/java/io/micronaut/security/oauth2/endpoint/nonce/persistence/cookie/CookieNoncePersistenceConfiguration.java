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
package io.micronaut.security.oauth2.endpoint.nonce.persistence.cookie;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.cookie.CookieConfiguration;
import io.micronaut.security.oauth2.endpoint.AbstractCookieConfiguration;
import io.micronaut.security.oauth2.endpoint.nonce.DefaultNonceConfiguration;

import java.time.Duration;
import java.time.temporal.TemporalAmount;
import java.util.Optional;

/**
 * @author James Kleeh
 * @since 1.2.0
 */
@ConfigurationProperties(CookieNoncePersistenceConfiguration.PREFIX)
public class CookieNoncePersistenceConfiguration extends AbstractCookieConfiguration implements CookieConfiguration {

    public static final String PREFIX = DefaultNonceConfiguration.PREFIX + ".cookie";

    private static final boolean DEFAULT_HTTPONLY = true;
    private static final String DEFAULT_COOKIENAME = "OPENID_NONCE";
    private static final String DEFAULT_COOKIEPATH = "/";
    private static final Duration DEFAULT_MAX_AGE = Duration.ofMinutes(5);

    private String cookiePath = DEFAULT_COOKIEPATH;
    private Boolean cookieHttpOnly = DEFAULT_HTTPONLY;
    private Duration cookieMaxAge = DEFAULT_MAX_AGE;
    private String cookieName = DEFAULT_COOKIENAME;

    @NonNull
    @Override
    public String getCookieName() {
        return this.cookieName;
    }

    /**
     * Cookie Name. Default value ({@value #DEFAULT_COOKIENAME}).
     *
     * @param cookieName Cookie name
     */
    public void setCookieName(@NonNull String cookieName) {
        this.cookieName = cookieName;
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
