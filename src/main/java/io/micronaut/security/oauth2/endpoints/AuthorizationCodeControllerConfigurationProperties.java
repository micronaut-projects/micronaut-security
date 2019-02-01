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

package io.micronaut.security.oauth2.endpoints;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.security.config.SecurityConfigurationProperties;

import javax.annotation.Nonnull;

/**
 * {@link ConfigurationProperties} implementation of {@link AuthorizationCodeControllerConfiguration}.
 *
 * @since 1.0.0
 * @author Sergio del Amo
 */
@ConfigurationProperties(AuthorizationCodeControllerConfigurationProperties.PREFIX)
public class AuthorizationCodeControllerConfigurationProperties implements AuthorizationCodeControllerConfiguration {
    public static final String PREFIX = SecurityConfigurationProperties.PREFIX + ".endpoints.authcode";

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;

    /**
     * The default path.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_CONTROLLERPATH = "/authcode";

    /**
     * The default code path.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_ACTIONPATH = "/cb";

    private boolean enabled = DEFAULT_ENABLED;

    @Nonnull
    private String controllerPath = DEFAULT_CONTROLLERPATH;

    @Nonnull
    private String  actionPath = DEFAULT_ACTIONPATH;

    /**
     * @return true if you want to enable the {@link AuthorizationCodeController}
     */
    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    /**
     * Sets whether the {@link AuthorizationCodeController} is enabled. Default value ({@value #DEFAULT_ENABLED}).
     *
     * @param enabled True if is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Nonnull
    @Override
    public String getControllerPath() {
        return controllerPath;
    }

    @Nonnull
    @Override
    public String getActionPath() {
        return actionPath;
    }

    /**
     * if the callback endpoint is /authcode/cb controller path will be /authcode.
     * Default value ({@value #DEFAULT_CONTROLLERPATH}).
     * @param controllerPath Controller's path
     */
    public void setControllerPath(@Nonnull String controllerPath) {
        this.controllerPath = controllerPath;
    }

    /**
     * if the callback endpoint is /authcode/cb controller action path will be /cb . Default value ({@value #DEFAULT_ACTIONPATH}).
     * @param actionPath Controller action path.
     */
    public void setActionPath(@Nonnull String actionPath) {
        this.actionPath = actionPath;
    }
}
