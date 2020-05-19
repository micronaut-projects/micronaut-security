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
package io.micronaut.security.session;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.config.RedirectConfigurationProperties;
import io.micronaut.security.config.SecurityConfigurationProperties;

/**
 * Implementation of {@link SecuritySessionConfiguration}. Session-based Authentication configuration properties.
 * @author Sergio del Amo
 * @since 1.0
 * @deprecated Use {@link RedirectConfigurationProperties} instead.
 */
@Deprecated
@ConfigurationProperties(SecuritySessionConfigurationProperties.PREFIX)
public class SecuritySessionConfigurationProperties implements SecuritySessionConfiguration {

    public static final String PREFIX = SecurityConfigurationProperties.PREFIX + ".session";

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;

    private final RedirectConfigurationProperties redirectConfigurationProperties;

    private boolean enabled = DEFAULT_ENABLED;

    /**
     *
     * @param redirectConfigurationProperties Redirect configuration
     */
    public SecuritySessionConfigurationProperties(RedirectConfigurationProperties redirectConfigurationProperties) {
        this.redirectConfigurationProperties = redirectConfigurationProperties;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    @Deprecated
    public String getLoginSuccessTargetUrl() {
        return this.redirectConfigurationProperties.getLoginSuccess();
    }

    @Override
    @Deprecated
    public String getLogoutTargetUrl() {
        return this.redirectConfigurationProperties.getLogout();
    }

    @Override
    @Deprecated
    public String getLoginFailureTargetUrl() {
        return this.redirectConfigurationProperties.getLoginFailure();
    }

    @Override
    @Deprecated
    public String getUnauthorizedTargetUrl()  {
        return this.redirectConfigurationProperties.getUnauthorized();
    }

    @Override
    @Deprecated
    public String getForbiddenTargetUrl()  {
        return this.redirectConfigurationProperties.getForbidden();
    }

    /**
     * deprecated use micronaut.security.redirect.login-success.
     *
     * @param loginSuccessTargetUrl The URL
     */
    @Deprecated
    public void setLoginSuccessTargetUrl(String loginSuccessTargetUrl) {
        if (StringUtils.isNotEmpty(loginSuccessTargetUrl)) {
            this.redirectConfigurationProperties.setLoginSuccess(loginSuccessTargetUrl);
        }
    }

    /**
     * deprecated use micronaut.security.redirect.login-success.
     *
     * @param loginFailureTargetUrl The URL
     */
    @Deprecated
    public void setLoginFailureTargetUrl(String loginFailureTargetUrl) {
        if (StringUtils.isNotEmpty(loginFailureTargetUrl)) {
            this.redirectConfigurationProperties.setLoginFailure(loginFailureTargetUrl);
        }
    }

    /**
     * deprecated use micronaut.security.redirect.logout
     *
     * @param logoutTargetUrl The URL
     */
    @Deprecated
    public void setLogoutTargetUrl(String logoutTargetUrl) {
        if (StringUtils.isNotEmpty(logoutTargetUrl)) {
            this.redirectConfigurationProperties.setLogout(logoutTargetUrl);
        }
    }

    /**
     * deprecated use micronaut.security.redirect.unauthorized
     *
     * @param unauthorizedTargetUrl The URL
     */
    @Deprecated
    public void setUnauthorizedTargetUrl(String unauthorizedTargetUrl) {
        if (StringUtils.isNotEmpty(unauthorizedTargetUrl)) {
            this.redirectConfigurationProperties.setUnauthorized(unauthorizedTargetUrl);
        }
    }

    /**
     * deprecated use micronaut.security.redirect.forbidden
     *
     * @param forbiddenTargetUrl The URL
     */
    @Deprecated
    public void setForbiddenTargetUrl(String forbiddenTargetUrl) {
        if (StringUtils.isNotEmpty(forbiddenTargetUrl)) {
            this.redirectConfigurationProperties.setForbidden(forbiddenTargetUrl);
        }
    }

    /**
     * Sets whether the session config is enabled. Default value ({@value #DEFAULT_ENABLED}).
     *
     * @param enabled True if it is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    @Deprecated
    public boolean isRedirectOnRejection() {
        return this.redirectConfigurationProperties.isOnRejection();
    }

    /**
     *  deprecated. use micronaut.security.redirect.on-rejection instead.
     *
     * @param redirectOnRejection True if a redirect should occur
     */
    @Deprecated
    public void setRedirectOnRejection(boolean redirectOnRejection) {
        this.redirectConfigurationProperties.setOnRejection(redirectOnRejection);
    }
}
