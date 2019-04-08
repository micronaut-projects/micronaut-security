/*
 * Copyright 2017-2019 original authors
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

package io.micronaut.security.oauth2.handlers;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.security.oauth2.openid.configuration.OpenIdProviderConfigurationProperties;
import io.micronaut.security.token.jwt.cookie.JwtCookieConfigurationProperties;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URI;
import java.time.temporal.TemporalAmount;
import java.util.Optional;

/**
 * {@link ConfigurationProperties} implementation of {@link CookieSuccessfulIdTokenAccessTokenResponseHandlerConfiguration}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@ConfigurationProperties(CookieSuccessfulIdTokenAccessTokenResponseHandlerConfigurationProperties.PREFIX)
public class CookieSuccessfulIdTokenAccessTokenResponseHandlerConfigurationProperties implements CookieSuccessfulIdTokenAccessTokenResponseHandlerConfiguration {

    public static final String PREFIX = OpenIdProviderConfigurationProperties.PREFIX + ".idtoken.cookie";

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;

    /**
     * The default login success target URL.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_LOGINSUCCESSTARGETURL = "/";

    /**
     * The default secure value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_SECURE = true;

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
     * The default value to always redirect to the default uri.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ALWAYS_REDIRECT = false;

    private String cookieName = JwtCookieConfigurationProperties.DEFAULT_COOKIENAME;
    private String cookieDomain;
    private String cookiePath = DEFAULT_COOKIEPATH;
    private URI defaultRedirectUri;
    private Boolean alwaysRedirectDefault = DEFAULT_ALWAYS_REDIRECT;
    private Boolean cookieHttpOnly = DEFAULT_HTTPONLY;
    private Boolean cookieSecure = DEFAULT_SECURE;
    private TemporalAmount cookieMaxAge;
    private boolean enabled = DEFAULT_ENABLED;

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Enables {@link io.micronaut.security.oauth2.handlers.CookieSuccessfulIdTokenAccessTokenResponseHandler}. Default value ({@value #DEFAULT_ENABLED}).
     * @param enabled enabled flag
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Cookie Name. Default value (JWT).
     * @param cookieName Cookie name
     */
    public void setCookieName(String cookieName) {
        this.cookieName = cookieName;
    }

    @Nonnull
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
    public Optional<Boolean> isCookieSecure() {
        return Optional.ofNullable(cookieSecure);
    }

    /**
     * @return The max age to use for the cookie
     */
    @Override
    public Optional<TemporalAmount> getCookieMaxAge() {
        return Optional.ofNullable(cookieMaxAge);
    }

    /**
     * Sets the domain name of this Cookie. Default value (JWT).
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
     * @param cookieHttpOnly Whether the Cookie can only be accessed via HTTP.
     */
    public void setCookieHttpOnly(boolean cookieHttpOnly) {
        this.cookieHttpOnly = cookieHttpOnly;
    }

    /**
     * Sets whether the cookie is secured. Default value ({@value #DEFAULT_SECURE}).
     * @param cookieSecure True if the cookie is secure
     */
    public void setCookieSecure(boolean cookieSecure) {
        this.cookieSecure = cookieSecure;
    }

    /**
     * Sets the maximum age of the cookie.
     * @param cookieMaxAge The maximum age of the cookie
     */
    public void setCookieMaxAge(TemporalAmount cookieMaxAge) {
        this.cookieMaxAge = cookieMaxAge;
    }

    @Override
    public Optional<URI> getDefaultRedirectUri() {
        return Optional.ofNullable(this.defaultRedirectUri);
    }

    /**
     * Sets the login success target URL. Default behavior is to redirect back to the original URI.
     *
     * @param defaultRedirectUri The URI
     */
    public void setDefaultRedirectUri(URI defaultRedirectUri) {
        this.defaultRedirectUri = defaultRedirectUri;
    }

    @Override
    public Boolean getAlwaysRedirectDefault() {
        return alwaysRedirectDefault;
    }

    /**
     * Sets whether the default redirect URI should always be used. Default value ({@value #DEFAULT_ALWAYS_REDIRECT}).
     *
     * @param alwaysRedirectDefault The always redirect setting
     */
    public void setAlwaysRedirectDefault(Boolean alwaysRedirectDefault) {
        this.alwaysRedirectDefault = alwaysRedirectDefault;
    }
}
