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
package io.micronaut.security.token.cookie;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.cookie.CookieConfiguration;
import io.micronaut.security.authentication.CookieBasedAuthenticationModeCondition;
import io.micronaut.security.token.config.TokenConfigurationProperties;
import java.util.Optional;

/**
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Requires(classes = CookieConfiguration.class)
@Requires(condition = CookieBasedAuthenticationModeCondition.class)
@Requires(property = TokenCookieConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE, defaultValue = StringUtils.TRUE)
@ConfigurationProperties(TokenCookieConfigurationProperties.PREFIX)
public class TokenCookieConfigurationProperties extends AbstractAccessTokenCookieConfigurationProperties implements AccessTokenCookieConfiguration {

    public static final String PREFIX = TokenConfigurationProperties.PREFIX + ".cookie";

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;

    /**
     * The default cookie name.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_COOKIENAME = "JWT";

    /**
     * Default Cookie Path.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_COOKIEPATH = "/";

    private String cookiePath = DEFAULT_COOKIEPATH;
    private boolean enabled = DEFAULT_ENABLED;
    private String cookieName = DEFAULT_COOKIENAME;

    /**
     *
     * @return a boolean flag indicating whether the JwtCookieTokenReader should be enabled or not
     */
    @Override
    public boolean isEnabled() {
        return enabled;
    }

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
     * @return The path of the cookie.
     */
    @Nullable
    @Override
    public Optional<String> getCookiePath() {
        return Optional.ofNullable(cookiePath);
    }

    /**
     * Sets the path of the cookie. Default value ({@value #DEFAULT_COOKIEPATH}).
     * @param cookiePath The path of the cookie.
     */
    public void setCookiePath(@Nullable String cookiePath) {
        this.cookiePath = cookiePath;
    }
}
