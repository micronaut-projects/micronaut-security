/*
 * Copyright 2017-2024 original authors
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
package io.micronaut.security.csrf;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.cookie.SameSite;
import io.micronaut.security.token.generator.AccessTokenConfigurationProperties;

import java.time.Duration;
import java.time.temporal.TemporalAmount;
import java.util.Optional;

@Internal
@ConfigurationProperties(CsrfConfiguration.PREFIX)
final class CsrfConfigurationProperties implements CsrfConfiguration {
    /**
     * The default HTTP Header name.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_HTTP_HEADER_NAME = "X-CSRF-TOKEN";

    /**
     * The default fieldName.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_FIELD_NAME = "csrfToken";

    /**
     * The default cookie name..
     * @see <a href="https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#using-cookies-with-host-prefixes-to-identify-origins">Using Cookies with Host Prefixes to Identify Origins</a>
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_COOKIE_NAME = "__Host-csrfToken";

    /**
     * The default HTTP Session name.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_HTTP_SESSION_NAME = "csrfToken";

    /**
     * The default Same Site Configuration.
     */
    @SuppressWarnings("WeakerAccess")
    public static final SameSite DEFAULT_SAME_SITE = SameSite.Strict;

    public static final int DEFAULT_RANDOM_VALUE_SIZE = 16;

    public static final boolean DEFAULT_ENABLED = true;

    private static final boolean DEFAULT_HTTPONLY = true;
    private static final String DEFAULT_COOKIEPATH = "/";
    private static final Boolean DEFAULT_SECURE = true;
    private static final Duration DEFAULT_MAX_AGE =  Duration.ofSeconds(AccessTokenConfigurationProperties.DEFAULT_EXPIRATION);

    private boolean enabled = DEFAULT_ENABLED;
    private String headerName = DEFAULT_HTTP_HEADER_NAME;
    private String fieldName = DEFAULT_FIELD_NAME;
    private int randomValueSize = DEFAULT_RANDOM_VALUE_SIZE;
    private String httpSessionName = DEFAULT_HTTP_SESSION_NAME;

    @Nullable
    private String cookieDomain;

    private Boolean cookieSecure = DEFAULT_SECURE;
    private String cookiePath = DEFAULT_COOKIEPATH;
    private Boolean cookieHttpOnly = DEFAULT_HTTPONLY;
    private Duration cookieMaxAge = DEFAULT_MAX_AGE;
    private String cookieName = DEFAULT_COOKIE_NAME;
    private SameSite sameSite = DEFAULT_SAME_SITE;

    @Nullable
    private String signatureKey;

    @Override
    @Nullable
    public String getSecretKey() {
        return signatureKey;
    }

    /**
     * The Secret Key that is used to calculate an HMAC as part of a CSRF token generation. Default Value `null`.
     * @param signatureKey The Secret Key that is used to calculate an HMAC as part of a CSRF token generation.
     */
    public void setSignatureKey(@Nullable String signatureKey) {
        this.signatureKey = signatureKey;
    }

    @Override
    @NonNull
    public String getHttpSessionName() {
        return httpSessionName;
    }

    /**
     * Key to look for the CSRF token in an HTTP Session. Default Value: {@value #DEFAULT_HTTP_SESSION_NAME}.
     * @param httpSessionName Key to look for the CSRF token in an HTTP Session.
     */
    public void setHttpSessionName(@NonNull String httpSessionName) {
        this.httpSessionName = httpSessionName;
    }

    @Override
    public int getRandomValueSize() {
        return randomValueSize;
    }

    /**
     * Random value's size in bytes. The random value used is used to build a CSRF Token. Default Value: {@value #DEFAULT_RANDOM_VALUE_SIZE}.
     * @param randomValueSize Random CSRF Token size in bytes.
     */
    public void setRandomValueSize(int randomValueSize) {
        this.randomValueSize = randomValueSize;
    }

    @Override
    @NonNull
    public String getHeaderName() {
        return headerName;
    }

    /**
     * HTTP Header name to look for the CSRF token. Default Value: {@value #DEFAULT_HTTP_HEADER_NAME}.
     * @param headerName HTTP Header name to look for the CSRF token.
     */
    public void setHeaderName(@NonNull String headerName) {
        this.headerName = headerName;
    }

    @Override
    @NonNull
    public String getFieldName() {
        return fieldName;
    }

    /**
     * Field name in a form url encoded submission  to look for the CSRF token. Default Value: {@value #DEFAULT_FIELD_NAME}.
     * @param fieldName Field name in a form url encoded submission  to look for the CSRF token.
     */
    public void setFieldName(@NonNull String fieldName) {
        this.fieldName = fieldName;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Whether the CSRF integration is enabled. Default value {@value #DEFAULT_ENABLED}.
     * @param enabled Whether the CSRF integration is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
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
        return this.cookieName;
    }

    /**
     * Cookie Name.
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
     * Sets the maximum age of the cookie. Default value ({@value AccessTokenConfigurationProperties#DEFAULT_EXPIRATION} seconds).
     *
     * @param cookieMaxAge The maximum age of the cookie
     */
    public void setCookieMaxAge(Duration cookieMaxAge) {
        this.cookieMaxAge = cookieMaxAge;
    }

    @Override
    public Optional<SameSite> getCookieSameSite() {
        return Optional.of(this.sameSite);
    }

    /**
     * Cookie Same Site Configuration. It defaults to Strict.
     * @param sameSite Same Site Configuration
     */
    public void setCookieSameSite(SameSite sameSite) {
        this.sameSite = sameSite;
    }
}
