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
package io.micronaut.security.token.jwt.endpoints;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.config.SecurityConfigurationProperties;

/**
 * Configures the provided {@link OauthController}.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Requires(property = OauthControllerConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE, defaultValue = StringUtils.TRUE)
@ConfigurationProperties(OauthControllerConfigurationProperties.PREFIX)
public class OauthControllerConfigurationProperties implements OauthControllerConfiguration {

    public static final String PREFIX = SecurityConfigurationProperties.PREFIX + ".endpoints.oauth";

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;

    /**
     * The default path.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_PATH = "/oauth/access_token";

    /**
     * Default Get Allowed.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_GETALLOWED = true;

    private boolean enabled = DEFAULT_ENABLED;
    private String path = DEFAULT_PATH;
    private boolean getAllowed = DEFAULT_GETALLOWED;

    /**
     * @return true if you want to enable the {@link OauthController}
     */
    @Override
    public boolean isEnabled() {
         return this.enabled;
    }

    @Override
    public String getPath() {
        return this.path;
    }

    /**
     * Sets whether the {@link io.micronaut.security.token.jwt.endpoints.OauthController} is enabled. Default value ({@value #DEFAULT_ENABLED}).
     *
     * @param enabled True if is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Sets the path to map the {@link io.micronaut.security.token.jwt.endpoints.OauthController} to. Default value ({@value #DEFAULT_PATH}).
     *
     * @param path The path
     */
    public void setPath(String path) {
        if (StringUtils.isNotEmpty(path)) {
            this.path = path;
        }
    }

    /**
     * @return True if refresh requests can be GET
     */
    @Override
    public boolean isGetAllowed() {
        return this.getAllowed;
    }

    /**
     *  Enables HTTP GET invocations of refresh token requests. Only applies
     *  to requests sending a cookie (JWT_REFRESH_TOKEN). Default value ({@value #DEFAULT_GETALLOWED}).
     * @param getAllowed Whether Http GET should be supported.
     */
    public void setGetAllowed(boolean getAllowed) {
        this.getAllowed = getAllowed;
    }
}
