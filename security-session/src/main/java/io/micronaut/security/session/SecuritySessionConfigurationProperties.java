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
import io.micronaut.core.value.PropertyResolver;
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

    private final PropertyResolver propertyResolver;
    private final RedirectConfigurationProperties redirectConfigurationProperties;

    private boolean enabled = DEFAULT_ENABLED;

    /**
     *
     * @param propertyResolver Property resolvers
     * @param redirectConfigurationProperties Redirect configuration
     */
    public SecuritySessionConfigurationProperties(PropertyResolver propertyResolver,
                                                  RedirectConfigurationProperties redirectConfigurationProperties) {
        this.propertyResolver = propertyResolver;
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
        return this.redirectConfigurationProperties.getUnauthorized().getUrl();
    }

    @Override
    @Deprecated
    public String getForbiddenTargetUrl()  {
        return this.redirectConfigurationProperties.getForbidden().getUrl();
    }

    /**
     * deprecated use micronaut.security.redirect.login-success.
     *
     * @param loginSuccessTargetUrl The URL
     */
    @Deprecated
    public void setLoginSuccessTargetUrl(String loginSuccessTargetUrl) {
        if (!propertyResolver.containsProperty(RedirectConfigurationProperties.PREFIX + ".login-success")) {
            if (StringUtils.isNotEmpty(loginSuccessTargetUrl)) {
                this.redirectConfigurationProperties.setLoginSuccess(loginSuccessTargetUrl);
            }
        }
    }

    /**
     * deprecated use micronaut.security.redirect.login-success.
     *
     * @param loginFailureTargetUrl The URL
     */
    @Deprecated
    public void setLoginFailureTargetUrl(String loginFailureTargetUrl) {
        if (!propertyResolver.containsProperty(RedirectConfigurationProperties.PREFIX + ".login-failure")) {
            if (StringUtils.isNotEmpty(loginFailureTargetUrl)) {
                this.redirectConfigurationProperties.setLoginFailure(loginFailureTargetUrl);
            }
        }
    }

    /**
     * deprecated use micronaut.security.redirect.logout
     *
     * @param logoutTargetUrl The URL
     */
    @Deprecated
    public void setLogoutTargetUrl(String logoutTargetUrl) {
        if (!propertyResolver.containsProperty(RedirectConfigurationProperties.PREFIX + ".logout")) {
            if (StringUtils.isNotEmpty(logoutTargetUrl)) {
                this.redirectConfigurationProperties.setLogout(logoutTargetUrl);
            }
        }
    }

    /**
     * deprecated use micronaut.security.redirect.unauthorized
     *
     * @param unauthorizedTargetUrl The URL
     */
    @Deprecated
    public void setUnauthorizedTargetUrl(String unauthorizedTargetUrl) {
        if (!propertyResolver.containsProperty(RedirectConfigurationProperties.PREFIX + ".unauthorized.url")) {
            if (StringUtils.isNotEmpty(unauthorizedTargetUrl)) {
                if (this.redirectConfigurationProperties.getUnauthorized() instanceof RedirectConfigurationProperties.UnauthorizedRedirectConfigurationProperties) {
                    ((RedirectConfigurationProperties.UnauthorizedRedirectConfigurationProperties) this.redirectConfigurationProperties.getUnauthorized()).setUrl(unauthorizedTargetUrl);
                }
            }
        }
    }

    /**
     * deprecated use micronaut.security.redirect.forbidden
     *
     * @param forbiddenTargetUrl The URL
     */
    @Deprecated
    public void setForbiddenTargetUrl(String forbiddenTargetUrl) {
        if (!propertyResolver.containsProperty(RedirectConfigurationProperties.PREFIX + ".forbidden.url")) {
            if (StringUtils.isNotEmpty(forbiddenTargetUrl)) {
                if (this.redirectConfigurationProperties.getForbidden() instanceof RedirectConfigurationProperties.ForbiddenRedirectConfigurationProperties) {
                    ((RedirectConfigurationProperties.ForbiddenRedirectConfigurationProperties) this.redirectConfigurationProperties.getForbidden()).setUrl(forbiddenTargetUrl);
                }
            }
        }
    }

    /**
     * Sets whether the session config is enabled. Default value ({@value #DEFAULT_ENABLED}).
     *
     * @param enabled True if it is enabled
     */
    @Deprecated
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    @Deprecated
    public boolean isRedirectOnRejection() {
        return this.redirectConfigurationProperties.getUnauthorized().isEnabled() &&
                this.redirectConfigurationProperties.getForbidden().isEnabled();
    }

    /**
     *  deprecated. use micronaut.security.redirect.on-rejection instead.
     *
     * @param redirectOnRejection True if a redirect should occur
     */
    @Deprecated
    public void setRedirectOnRejection(boolean redirectOnRejection) {
        if (!propertyResolver.containsProperty(RedirectConfigurationProperties.PREFIX + ".unauthorized.enabled") &&
            !propertyResolver.containsProperty(RedirectConfigurationProperties.PREFIX + ".forbidden.enabled")) {
            if (this.redirectConfigurationProperties.getUnauthorized() instanceof RedirectConfigurationProperties.UnauthorizedRedirectConfigurationProperties) {
                ((RedirectConfigurationProperties.UnauthorizedRedirectConfigurationProperties) this.redirectConfigurationProperties.getUnauthorized()).setEnabled(redirectOnRejection);
            }
            if (this.redirectConfigurationProperties.getForbidden() instanceof RedirectConfigurationProperties.ForbiddenRedirectConfigurationProperties) {
                ((RedirectConfigurationProperties.ForbiddenRedirectConfigurationProperties) this.redirectConfigurationProperties.getForbidden()).setEnabled(redirectOnRejection);
            }
        }
    }
}
