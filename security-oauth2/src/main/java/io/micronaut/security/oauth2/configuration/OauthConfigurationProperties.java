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
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.oauth2.configuration.endpoints.EndSessionConfiguration;

import javax.annotation.Nonnull;
import javax.validation.constraints.NotNull;
import java.util.Optional;

/**
 * {@link ConfigurationProperties} implementation of {@link OauthClientConfiguration}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Requires(property = OauthConfigurationProperties.PREFIX + ".enabled", value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@ConfigurationProperties(OauthConfigurationProperties.PREFIX)
public class OauthConfigurationProperties implements OauthConfiguration {
    public static final String PREFIX = SecurityConfigurationProperties.PREFIX + ".oauth2";

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;
    private static final String DEFAULT_LOGIN = "/oauth/login/{provider}";
    private static final String DEFAULT_CALLBACK = "/oauth/callback/{provider}";
    private static final String DEFAULT_LOGOUT = "/oauth/logout/{provider}";

    private boolean enabled = DEFAULT_ENABLED;
    private String callbackUri = DEFAULT_CALLBACK;
    private String loginUri = DEFAULT_LOGIN;
    private String logoutUri = DEFAULT_LOGOUT;
    private OpenIdConfigurationProperties openid;

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

    @Override
    public String getLoginUri() {
        return loginUri;
    }

    /**
     *
     * @param loginUri The Login uri
     */
    public void setLoginUri(String loginUri) {
        this.loginUri = loginUri;
    }

    @Override
    public String getCallbackUri() {
        return callbackUri;
    }

    /**
     *
     * @param callbackUri The callback Uri
     */
    public void setCallbackUri(String callbackUri) {
        this.callbackUri = callbackUri;
    }


    @Override
    public String getLogoutUri() {
        return logoutUri;
    }

    public void setLogoutUri(String logoutUri) {
        this.logoutUri = logoutUri;
    }

    @Override
    public Optional<OpenIdConfiguration> getOpenid() {
        return Optional.ofNullable(openid);
    }

    public void setOpenid(OpenIdConfigurationProperties openid) {
        this.openid = openid;
    }

    @ConfigurationProperties("openid")
    public static class OpenIdConfigurationProperties implements OpenIdConfiguration {

        public static final String PREFIX = OauthConfigurationProperties.PREFIX + ".openid";

        private EndSessionConfigurationProperties endSession = new EndSessionConfigurationProperties();

        @Override
        public Optional<EndSessionConfiguration> getEndSession() {
            return Optional.of(endSession);
        }

        public void setEndSession(EndSessionConfigurationProperties endSession) {
            this.endSession = endSession;
        }


        @ConfigurationProperties("end-session")
        public static class EndSessionConfigurationProperties implements EndSessionConfiguration {

            public static final String PREFIX = OpenIdConfigurationProperties.PREFIX + ".end-session";

            private static final String DEFAULT_VIEW_MODEL_KEY = "endSessionUrl";

            private String viewModelKey = DEFAULT_VIEW_MODEL_KEY;
            private String redirectUri = "/logout";

            @Override
            @Nonnull
            public String getViewModelKey() {
                return viewModelKey;
            }

            /**
             * The key to reference the end session URL in a view. Default value ({@value #DEFAULT_VIEW_MODEL_KEY}).
             *
             * @param viewModelKey
             */
            public void setViewModelKey(String viewModelKey) {
                this.viewModelKey = viewModelKey;
            }

            @Override
            @Nonnull
            public String getRedirectUri() {
                return redirectUri;
            }

            /**
             *
             * @param redirectUri Redirect uri
             */
            public void setRedirectUri(String redirectUri) {
                this.redirectUri = redirectUri;
            }
        }

    }
}
