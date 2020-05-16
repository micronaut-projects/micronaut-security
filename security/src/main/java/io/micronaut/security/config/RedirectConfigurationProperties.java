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

package io.micronaut.security.config;

import edu.umd.cs.findbugs.annotations.NonNull;
import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.util.StringUtils;

import javax.validation.constraints.NotBlank;

/**
 * {@link ConfigurationProperties} implementation of {@link RedirectConfiguration}.
 *
 * @author Sergio del Amo
 * @since 2.0.0
 */
@ConfigurationProperties(RedirectConfigurationProperties.PREFIX)
public class RedirectConfigurationProperties implements RedirectConfiguration {
    public static final String PREFIX = SecurityConfigurationProperties.PREFIX + ".redirect";

    /**
     * The default logout URL.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_LOGOUT_URL = "/";

    /**
     * The default login success target URL.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_LOGIN_SUCCESS = "/";

    /**
     * The default login failure target URL.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_LOGIN_FAILURE = "/";

    /**
     * The default unauthorized rejection target URL.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_UNAUTHORIZED = "/";

    /**
     * The default forbidden rejection target URL.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_FORBIDDEN = "/";

    /**
     * The default forbidden redirect on rejection.
     */
    @SuppressWarnings("WeakerAccess")
    private static final Boolean DEFAULT_ON_REJECTION = true;

    @NonNull
    @NotBlank
    private String unauthorized = DEFAULT_UNAUTHORIZED;

    @NonNull
    @NotBlank
    private String forbidden = DEFAULT_FORBIDDEN;

    private boolean onRejection = DEFAULT_ON_REJECTION;

    @NonNull
    @NotBlank
    private String loginSuccess = DEFAULT_LOGIN_SUCCESS;

    @NonNull
    @NotBlank
    private String loginFailure = DEFAULT_LOGIN_FAILURE;

    @NonNull
    @NotBlank
    private String logout = DEFAULT_LOGOUT_URL;

    @Override
    @NonNull
    public String getUnauthorized()  {
        return unauthorized;
    }

    @Override
    @NonNull
    public String getForbidden()  {
        return forbidden;
    }

    /**
     * Where the user is redirected to after trying to access a secured route. Default value ({@value #DEFAULT_UNAUTHORIZED}).
     *
     * @param unauthorized The URL
     */
    public void setUnauthorized(@NonNull String unauthorized) {
        if (StringUtils.isNotEmpty(unauthorized)) {
            this.unauthorized = unauthorized;
        }
    }

    /**
     * Where the user is redirected to after trying to access a secured route for which the does not have sufficient roles.. Default value ({@value #DEFAULT_FORBIDDEN}).
     *
     * @param forbidden The URL
     */
    public void setForbidden(@NonNull String forbidden) {
        if (StringUtils.isNotEmpty(forbidden)) {
            this.forbidden = forbidden;
        }
    }

    @Override
    public boolean isOnRejection() {
        return onRejection;
    }

    /**
     * Sets whether a redirect should occur on an authorization failure.
     * Default value ({@value #DEFAULT_ON_REJECTION}).
     *
     * @param onRejection True if a redirect should occur
     */
    public void setOnRejection(boolean onRejection) {
        this.onRejection = onRejection;
    }

    @NonNull
    @Override
    public String getLoginSuccess() {
        return loginSuccess;
    }

    @NonNull
    @Override
    public String getLoginFailure() {
        return loginFailure;
    }

    /**
     * Where the user is redirected to after a successful login. Default value ({@value #DEFAULT_LOGIN_SUCCESS}).
     *
     * @param loginSuccess The URL
     */
    public void setLoginSuccess(@NonNull String loginSuccess) {
        this.loginSuccess = loginSuccess;
    }

    /**
     * Where the user is redirected to after a failed login. Default value ({@value #DEFAULT_LOGIN_FAILURE}).
     *
     * @param loginFailure The URL
     */
    public void setLoginFailure(@NonNull String loginFailure) {
        this.loginFailure = loginFailure;
    }

    @Override
    @NonNull
    public String getLogout() {
        return this.logout;
    }

    /**
     * URL where the user is redirected after logout. Default value ({@value #DEFAULT_LOGOUT_URL}).
     * @param logout The URL
     */
    public void setLogout(@NonNull String logout) {
        if (StringUtils.isNotEmpty(logout)) {
            this.logout = logout;
        }
    }
}
