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
     * The default behavior of redirect to the uri prior to login
     */
    public static final boolean DEFAULT_PRIOR_TO_LOGIN = false;

    @NonNull
    @NotBlank
    private String loginSuccess = DEFAULT_LOGIN_SUCCESS;

    @NonNull
    @NotBlank
    private String loginFailure = DEFAULT_LOGIN_FAILURE;

    @NonNull
    @NotBlank
    private String logout = DEFAULT_LOGOUT_URL;

    private boolean priorToLogin = DEFAULT_PRIOR_TO_LOGIN;

    private UnauthorizedRedirectConfigurationProperties unauthorized = new UnauthorizedRedirectConfigurationProperties();

    private ForbiddenRedirectConfigurationProperties forbidden = new ForbiddenRedirectConfigurationProperties();

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

    @NonNull
    @Override
    public UnauthorizedRedirectConfiguration getUnauthorized() {
        return unauthorized;
    }

    /**
     * Sets the unauthorized redirect configuration.
     *
     * @param unauthorized unauthorized redirect configuration.
     */
    public void setUnauthorized(UnauthorizedRedirectConfigurationProperties unauthorized) {
        this.unauthorized = unauthorized;
    }

    /**
     * Sets the forbidden redirect configuration.
     *
     * @param forbidden forbidden redirect configuration.
     */
    public void setForbidden(ForbiddenRedirectConfigurationProperties forbidden) {
        this.forbidden = forbidden;
    }

    @NonNull
    @Override
    public ForbiddenRedirectConfiguration getForbidden() {
        return forbidden;
    }

    /** If true, the user should be redirected back to the unauthorized
     * request that initiated the login flow. Supersedes the <code>login-success</code>
     * configuration for those cases. Default value {@value DEFAULT_PRIOR_TO_LOGIN}.
     *
     * @param priorToLogin Prior to login setting
     */
    public void setPriorToLogin(boolean priorToLogin) {
        this.priorToLogin = priorToLogin;
    }

    @Override
    public boolean isPriorToLogin() {
        return priorToLogin;
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

    /**
     * Unauthorized redirect configuration.
     */
    @ConfigurationProperties("unauthorized")
    public static class UnauthorizedRedirectConfigurationProperties implements UnauthorizedRedirectConfiguration {

        /**
         * The default enabled value for unauthorized.
         */
        @SuppressWarnings("WeakerAccess")
        public static final Boolean DEFAULT_ENABLED = true;

        /**
         * The default unauthorized rejection target URL.
         */
        @SuppressWarnings("WeakerAccess")
        public static final String DEFAULT_UNAUTHORIZED = "/";

        private boolean enabled = DEFAULT_ENABLED;

        @NonNull
        @NotBlank
        private String url = DEFAULT_UNAUTHORIZED;

        @Override
        @NonNull
        public String getUrl()  {
            return url;
        }

        /**
         * Where the user is redirected to after trying to access a secured route. Default value ({@value #DEFAULT_UNAUTHORIZED}).
         *
         * @param url The URL
         */
        public void setUrl(@NonNull String url) {
            if (StringUtils.isNotEmpty(url)) {
                this.url = url;
            }
        }

        @Override
        public boolean isEnabled() {
            return enabled;
        }

        /**
         * Whether it should redirect on unauthorized rejections. Default value ({@value #DEFAULT_ENABLED}).
         *
         * @param enabled The enabled flag
         */
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }

    /**
     * Forbidden redirect configuration.
     */
    @ConfigurationProperties("forbidden")
    public static class ForbiddenRedirectConfigurationProperties implements ForbiddenRedirectConfiguration {

        /**
         * The default enabled value for forbidden.
         */
        public static final Boolean DEFAULT_ENABLED = true;

        /**
         * The default forbidden rejection target URL.
         */
        @SuppressWarnings("WeakerAccess")
        public static final String DEFAULT_FORBIDDEN = "/";

        private boolean enabled = DEFAULT_ENABLED;

        @NonNull
        @NotBlank
        private String url = DEFAULT_FORBIDDEN;

        @Override
        @NonNull
        public String getUrl()  {
            return url;
        }

        /**
         * Where the user is redirected to after trying to access a secured route which he is forbidden to access. Default value ({@value #DEFAULT_FORBIDDEN}).
         *
         * @param url The URL
         */
        public void setUrl(@NonNull String url) {
            if (StringUtils.isNotEmpty(url)) {
                this.url = url;
            }
        }

        @Override
        public boolean isEnabled() {
            return enabled;
        }

        /**
         * Whether it should redirect on forbidden rejections. Default value ({@value #DEFAULT_ENABLED}).
         *
         * @param enabled The enabled flag
         */
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }
}
