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

package io.micronaut.security.oauth2.configuration;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.core.util.Toggleable;
import io.micronaut.security.config.SecurityConfigurationProperties;

/**
 * {@link ConfigurationProperties} implementation of {@link OauthClientConfiguration}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Requires(property = OauthConfigurationProperties.PREFIX + ".enabled", value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@ConfigurationProperties(OauthConfigurationProperties.PREFIX)
public class OauthConfigurationProperties implements Toggleable {
    public static final String PREFIX = SecurityConfigurationProperties.PREFIX + ".oauth2";

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;
    private static final String DEFAULT_LOGIN = "/oauth/login/{provider}";
    private static final String DEFAULT_CALLBACK = "/oauth/callback/{provider}";


    private boolean enabled = DEFAULT_ENABLED;
    private String callbackUrl = DEFAULT_CALLBACK;
    private String loginUrl = DEFAULT_LOGIN;

    /**
     * @return true if you want to enable the {@link OauthClientConfiguration}
     */
    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    /**
     * Sets whether the {@link OauthClientConfiguration} is enabled. Default value ({@value #DEFAULT_ENABLED}).
     *
     * @param enabled True if is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getLoginUrl() {
        return loginUrl;
    }

    public void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
    }

    public String getCallbackUrl() {
        return callbackUrl;
    }

    public void setCallbackUrl(String callbackUrl) {
        this.callbackUrl = callbackUrl;
    }
}
