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
     * The default callback path.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_CALLBACK = "/cb";

    /**
     * The default login path.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_LOGIN = "/login";

    private boolean enabled = DEFAULT_ENABLED;
    private String controllerPath = DEFAULT_CONTROLLERPATH;
    private String callbackPath = DEFAULT_CALLBACK;
    private String loginPath = DEFAULT_LOGIN;

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
    public String getCallbackPath() {
        return callbackPath;
    }

    @Nonnull
    @Override
    public String getLoginPath() {
        return loginPath;
    }

    /**
     * The authorization controller path. Default value ({@value #DEFAULT_CONTROLLERPATH}).
     *
     * @param controllerPath Controller's path
     */
    public void setControllerPath(@Nonnull String controllerPath) {
        this.controllerPath = controllerPath;
    }

    /**
     * Sets the path used by OAuth providers to callback the application. The value is appended
     * to the controller path value. Default value ({@value #DEFAULT_CALLBACK}).
     *
     * @param callbackPath Controller callback path.
     */
    public void setCallbackPath(@Nonnull String callbackPath) {
        this.callbackPath = callbackPath;
    }

    /**
     * Sets the path used to trigger a redirect to login with OAuth. The value is appended to
     * the controller path value. Default value ({@value #DEFAULT_LOGIN}).
     *
     * @param loginPath Controller login path.
     */
    public void setLoginPath(@Nonnull String loginPath) {
        this.loginPath = loginPath;
    }
}
