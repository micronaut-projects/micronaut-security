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
package io.micronaut.security.oauth2.configuration;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.oauth2.configuration.endpoints.EndSessionConfiguration;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Optional;

/**
 * {@link ConfigurationProperties} implementation of {@link OauthClientConfiguration}.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Requires(property = OauthConfigurationProperties.PREFIX + ".enabled", value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@ConfigurationProperties(OauthConfigurationProperties.PREFIX)
public class OauthConfigurationProperties implements OauthConfiguration {

    public static final String PREFIX = SecurityConfigurationProperties.PREFIX + ".oauth2";

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = false;
    private static final String DEFAULT_LOGIN = "/oauth/login{/provider}";
    private static final String DEFAULT_CALLBACK = "/oauth/callback{/provider}";

    private boolean enabled = DEFAULT_ENABLED;
    private String callbackUri = DEFAULT_CALLBACK;
    private String loginUri = DEFAULT_LOGIN;
    private String defaultProvider = null;

    private OpenIdConfigurationProperties openid = new OpenIdConfigurationProperties();

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    /**
     * Sets whether the OAuth 2.0 support is enabled. Default value ({@value #DEFAULT_ENABLED}).
     *
     * @param enabled True if is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    @Nonnull
    public String getLoginUri() {
        return loginUri;
    }

    /**
     * The URI template that is used to initiate an OAuth 2.0
     * authorization code grant flow. Default value ({@value #DEFAULT_LOGIN}).
     *
     * @param loginUri The Login uri
     */
    public void setLoginUri(@Nonnull String loginUri) {
        this.loginUri = loginUri;
    }

    @Override
    @Nonnull
    public String getCallbackUri() {
        return callbackUri;
    }

    /**
     * The default authentication provider for an OAuth 2.0 authorization code grant flow.
     *
     * @param defaultProvider The default authentication provider
     */
    public void setDefaultProvider(String defaultProvider) {
        this.defaultProvider = defaultProvider;
    }

    @Override
    @Nullable
    public Optional<String> getDefaultProvider() {
        return Optional.ofNullable(defaultProvider);
    }

    /**
     * The URI template that OAuth 2.0 providers can use to
     * submit an authorization callback request. Default value ({@value #DEFAULT_CALLBACK}).
     *
     * @param callbackUri The callback Uri
     */
    public void setCallbackUri(@Nonnull String callbackUri) {
        this.callbackUri = callbackUri;
    }

    @Override
    @Nonnull
    public OpenIdConfiguration getOpenid() {
        return openid;
    }

    /**
     * The OpenID configuration
     *
     * @param openid The OpenID configuration
     */
    public void setOpenid(@Nonnull OpenIdConfigurationProperties openid) {
        this.openid = openid;
    }

    /**
     * OpenID configuration
     */
    @ConfigurationProperties("openid")
    public static class OpenIdConfigurationProperties implements OpenIdConfiguration {

        public static final String PREFIX = OauthConfigurationProperties.PREFIX + ".openid";

        private static final String DEFAULT_LOGOUT = "/oauth/logout";

        private String logoutUri = DEFAULT_LOGOUT;
        private EndSessionConfigurationProperties endSession = new EndSessionConfigurationProperties();
        private ClaimsValidationConfigurationProperties claimsValidation = new ClaimsValidationConfigurationProperties();
        private AdditionalClaimsConfigurationProperties additionalClaims = new AdditionalClaimsConfigurationProperties();

        @Override
        public String getLogoutUri() {
            return logoutUri;
        }

        /**
         * The URI used to log out of an OpenID provider. Default value ({@value #DEFAULT_LOGOUT}).
         *
         * @param logoutUri The logout uri
         */
        public void setLogoutUri(String logoutUri) {
            this.logoutUri = logoutUri;
        }

        @Override
        public Optional<EndSessionConfiguration> getEndSession() {
            return Optional.of(endSession);
        }

        /**
         * The end session configuration
         *
         * @param endSession The end session configuration
         */
        public void setEndSession(EndSessionConfigurationProperties endSession) {
            this.endSession = endSession;
        }

        /**
         * @return Claims Validator Configuration
         */
        public ClaimsValidationConfigurationProperties getClaimsValidation() {
            return claimsValidation;
        }

        /**
         * @param claimsValidator Claims Validator Configuration
         */
        public void setClaimsValidation(ClaimsValidationConfigurationProperties claimsValidator) {
            this.claimsValidation = claimsValidator;
        }

        @Override
        public AdditionalClaimsConfigurationProperties getAdditionalClaims() {
            return additionalClaims;
        }

        /**
         * @param claims The Claims Configuration
         */
        public void setAdditionalClaims(AdditionalClaimsConfigurationProperties claims) {
            this.additionalClaims = claims;
        }

        /**
         * End session configuration
         */
        @ConfigurationProperties("end-session")
        public static class EndSessionConfigurationProperties implements EndSessionConfiguration {

            private static final String DEFAULT_REDIRECT_URI = "/logout";

            private String redirectUri = DEFAULT_REDIRECT_URI;

            @Override
            @Nonnull
            public String getRedirectUri() {
                return redirectUri;
            }

            /**
             * The URI the OpenID provider should redirect to after logging out. Default value ({@value #DEFAULT_REDIRECT_URI}).
             *
             * @param redirectUri Redirect uri
             */
            public void setRedirectUri(String redirectUri) {
                this.redirectUri = redirectUri;
            }
        }

        /**
         * Claims Validator configuration.
         */
        @ConfigurationProperties("claims-validation")
        public static class ClaimsValidationConfigurationProperties implements OpenIdClaimsValidationConfiguration {

            public static final String PREFIX = OpenIdConfigurationProperties.PREFIX + ".claims-validation";

            private static final boolean DEFAULT_ISSUER_ENABLED = true;
            private static final boolean DEFAULT_AUDIENCE_ENABLED = true;
            private static final boolean DEFAULT_AUTHORIZED_PARTY_ENABLED = true;

            private boolean issuer = DEFAULT_ISSUER_ENABLED;
            private boolean audience = DEFAULT_AUDIENCE_ENABLED;
            private boolean authorizedParty = DEFAULT_AUTHORIZED_PARTY_ENABLED;

            @Override
            public boolean isIssuer() {
                return issuer;
            }

            /**
             * @param issuer Whether {@link io.micronaut.security.oauth2.endpoint.token.response.validation.IssuerClaimValidator}
             *               is enabled. Default value ({@value #DEFAULT_ISSUER_ENABLED}).
             */
            public void setIssuer(boolean issuer) {
                this.issuer = issuer;
            }

            @Override
            public boolean isAudience() {
                return audience;
            }

            /**
             * @param audience Whether {@link io.micronaut.security.oauth2.endpoint.token.response.validation.AudienceClaimValidator}
             *                 is enabled. Default value ({@value #DEFAULT_AUDIENCE_ENABLED}).
             */
            public void setAudience(boolean audience) {
                this.audience = audience;
            }

            @Override
            public boolean isAuthorizedParty() {
                return authorizedParty;
            }

            /**
             * @param authorizedParty Whether {@link io.micronaut.security.oauth2.endpoint.token.response.validation.AuthorizedPartyClaimValidator}
             *                        is enabled. Default value ({@value #DEFAULT_AUTHORIZED_PARTY_ENABLED}).
             */
            public void setAuthorizedParty(boolean authorizedParty) {
                this.authorizedParty = authorizedParty;
            }
        }

        /**
         * Claims configuration.
         */
        @ConfigurationProperties("additional-claims")
        public static class AdditionalClaimsConfigurationProperties implements OpenIdAdditionalClaimsConfiguration {

            public static final String PREFIX = OpenIdConfigurationProperties.PREFIX + ".additional-claims";

            private boolean jwt;
            private boolean accessToken;
            private boolean refreshToken;

            @Override
            public boolean isJwt() {
                return jwt;
            }

            /**
             * Set to true if the original JWT from the provider should be included in the Micronaut JWT.
             * Default value (false).
             *
             * @param jwt The jwt
             */
            public void setJwt(boolean jwt) {
                this.jwt = jwt;
            }

            @Override
            public boolean isAccessToken() {
                return accessToken;
            }

            /**
             * Set to true if the original access token from the provider should be included in the Micronaut JWT.
             * Default value (false).
             *
             * @param accessToken Access token
             */
            public void setAccessToken(boolean accessToken) {
                this.accessToken = accessToken;
            }

            @Override
            public boolean isRefreshToken() {
                return refreshToken;
            }

            /**
             * Set to true if the original refresh token from the provider should be included in the Micronaut JWT.
             * Default value (false).
             *
             * @param refreshToken Refresh token
             */
            public void setRefreshToken(boolean refreshToken) {
                this.refreshToken = refreshToken;
            }
        }
    }
}
