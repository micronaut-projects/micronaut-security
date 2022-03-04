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

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.cookie.SameSite;
import io.micronaut.security.authentication.CookieBasedAuthenticationModeCondition;
import io.micronaut.security.token.jwt.config.JwtConfigurationProperties;

/**
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Requires(condition = CookieBasedAuthenticationModeCondition.class)
@Requires(property = JwtCookieConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE, defaultValue = StringUtils.TRUE)
@ConfigurationProperties(JwtCookieConfigurationProperties.PREFIX)
public class JwtCookieConfigurationProperties extends AbstractAccessTokenCookieConfigurationProperties {

    public static final String PREFIX = JwtConfigurationProperties.PREFIX + ".cookie";

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;

    /**
     * The default http only value.
     *
     * @deprecated use {@link AbstractAccessTokenCookieConfigurationProperties#DEFAULT_HTTPONLY}
     */
    @Deprecated
    public static final boolean DEFAULT_HTTPONLY = AbstractAccessTokenCookieConfigurationProperties.DEFAULT_HTTPONLY;

    /**
     * The default cookie name.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_COOKIENAME = "JWT";

    /**
     * Default Cookie Path.
     *
     * @deprecated use {@link AbstractAccessTokenCookieConfigurationProperties#DEFAULT_COOKIEPATH}
     */
    @Deprecated
    public static final String DEFAULT_COOKIEPATH = AbstractAccessTokenCookieConfigurationProperties.DEFAULT_COOKIEPATH;

    /**
     * The default same-site setting for the JWT cookie.
     *
     * @deprecated use {@link AbstractAccessTokenCookieConfigurationProperties#DEFAULT_COOKIESAMESITE}
     */
    @Deprecated
    public static final SameSite DEFAULT_COOKIESAMESITE = AbstractAccessTokenCookieConfigurationProperties.DEFAULT_COOKIESAMESITE;

    protected boolean enabled = DEFAULT_ENABLED;
    protected String cookieName = DEFAULT_COOKIENAME;


    /**
     * Sets whether JWT cookie configuration is enabled. Default value ({@value #DEFAULT_ENABLED}).
     * @param enabled True if it is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Cookie Name. Default value ({@value #DEFAULT_COOKIENAME}).
     * @param cookieName Cookie name
     */
    public void setCookieName(String cookieName) {
        this.cookieName = cookieName;
    }

}
