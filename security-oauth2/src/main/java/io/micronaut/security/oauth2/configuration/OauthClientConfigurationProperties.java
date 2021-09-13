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
import io.micronaut.context.annotation.Context;
import io.micronaut.context.annotation.EachProperty;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.core.convert.format.MapFormat;
import io.micronaut.http.MediaType;
import io.micronaut.security.oauth2.client.clientcredentials.ClientCredentialsConfiguration;
import io.micronaut.security.oauth2.client.clientcredentials.propagation.ClientCredentialsHeaderTokenPropagatorConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.*;
import io.micronaut.security.oauth2.grants.GrantType;
import io.micronaut.security.oauth2.endpoint.authorization.request.Display;
import io.micronaut.security.oauth2.endpoint.authorization.request.OpenIdScope;
import io.micronaut.security.oauth2.endpoint.authorization.request.Prompt;
import io.micronaut.security.oauth2.endpoint.authorization.request.ResponseType;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import java.net.URL;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Stores configuration of each configured OAuth 2.0 client.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Context
@EachProperty(OauthConfigurationProperties.PREFIX + ".clients")
public class OauthClientConfigurationProperties implements OauthClientConfiguration {

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;

    // If you change the default, edit the javadoc of `setScopes` which is exposed in the docs.
    private static final List<String> DEFAULT_SCOPES_OPENID = Arrays.asList(OpenIdScope.OPENID.toString(),
            OpenIdScope.EMAIL.toString(),
            OpenIdScope.PROFILE.toString());
    private List<String> DEFAULT_SCOPES = new ArrayList<>();

    private final String name;
    private String clientId;
    private String clientSecret;
    private List<String> scopes;
    private boolean enabled = DEFAULT_ENABLED;
    private GrantType grantType = GrantType.AUTHORIZATION_CODE;
    private AuthorizationEndpointConfigurationProperties authorization;
    private TokenEndpointConfigurationProperties token;
    private IntrospectionEndpointConfigurationProperties introspection;
    private RevocationEndpointConfigurationProperties revocation;
    private OpenIdClientConfigurationProperties openid;
    private ClientCredentialsConfigurationProperties clientCredentials;

    /**
     * @param name The provider name
     */
    public OauthClientConfigurationProperties(@Parameter String name) {
        this.name = name;
    }

    @NonNull
    @Override
    public String getClientId() {
        return clientId;
    }

    /**
     * OAuth 2.0 client id.
     *
     * @param clientId The client id
     */
    public void setClientId(@NonNull String clientId) {
        this.clientId = clientId;
    }

    @Nullable
    @Override
    public String getClientSecret() {
        return clientSecret;
    }

    /**
     * OAuth 2.0 client secret.
     *
     * @param clientSecret The client secret
     */
    public void setClientSecret(@Nullable String clientSecret) {
        this.clientSecret = clientSecret;
    }

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    /**
     * Sets whether the client is enabled. Default value ({@value #DEFAULT_ENABLED}).
     *
     * @param enabled The enabled flag
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @NonNull
    @Override
    public List<String> getScopes() {
        return scopes == null ? DEFAULT_SCOPES : scopes;
    }

    /**
     * Requested scopes. If not specified for OAuth 2.0 clients using OpenID Connect it defaults to `profile`, `email` and `idtoken`
     *
     * @param scopes The scopes
     */
    public void setScopes(List<String> scopes) {
        this.scopes = scopes;
    }

    @NonNull
    @Override
    public String getName() {
        return name;
    }

    @NonNull
    @Override
    public GrantType getGrantType() {
        return grantType;
    }

    /**
     * OAuth 2.0 grant type. Default value (authorization_code).
     *
     * @param grantType The grant type
     */
    public void setGrantType(@NonNull GrantType grantType) {
        this.grantType = grantType;
    }

    @Override
    public Optional<SecureEndpointConfiguration> getToken() {
        return Optional.ofNullable(token);
    }

    /**
     * The OAuth 2.0 token endpoint configuration.
     *
     * @param token The token endpoint configuration
     */
    public void setToken(TokenEndpointConfigurationProperties token) {
        this.token = token;
    }

    @Override
    public Optional<EndpointConfiguration> getAuthorization() {
        return Optional.ofNullable(authorization);
    }

    @Override
    @NonNull
    public Optional<ClientCredentialsConfiguration> getClientCredentials() {
        return Optional.ofNullable(clientCredentials);
    }

    /**
     * Sets the Client Credentials configuration.
     *
     * @param clientCredentials client credentials configuration
     */
    public void setClientCredentials(@NonNull ClientCredentialsConfigurationProperties clientCredentials) {
        this.clientCredentials = clientCredentials;
    }

    /**
     * The OAuth 2.0 authorization endpoint configuration.
     *
     * @param authorization The authorization endpoint configuration
     */
    public void setAuthorization(AuthorizationEndpointConfigurationProperties authorization) {
        this.authorization = authorization;
    }

    /**
     * @return The open id configuration
     */
    public Optional<OpenIdClientConfiguration> getOpenid() {
        return Optional.ofNullable(openid);
    }

    /**
     * The open id configuration.
     *
     * @param openid The open id configuration
     */
    public void setOpenid(OpenIdClientConfigurationProperties openid) {
        this.openid = openid;
        this.DEFAULT_SCOPES = DEFAULT_SCOPES_OPENID;
    }

    @Override
    public Optional<SecureEndpointConfiguration> getIntrospection() {
        return Optional.ofNullable(introspection);
    }

    /**
     * Sets the introspection endpoint configuration.
     *
     * @param introspection The introspection endpoint configuration
     */
    public void setIntrospection(IntrospectionEndpointConfigurationProperties introspection) {
        this.introspection = introspection;
    }

    @Override
    public Optional<SecureEndpointConfiguration> getRevocation() {
        return Optional.ofNullable(revocation);
    }

    /**
     * Sets the revocation endpoint configuration.
     *
     * @param revocation The revocation endpoint configuration
     */
    public void setRevocation(RevocationEndpointConfigurationProperties revocation) {
        this.revocation = revocation;
    }

    /**
     * Client credentials configuration.
     */
    @ConfigurationProperties("client-credentials")
    public static class ClientCredentialsConfigurationProperties implements ClientCredentialsConfiguration {

        /**
         * The default enable value.
         */
        @SuppressWarnings("WeakerAccess")
        public static final boolean DEFAULT_ENABLED = true;

        private boolean enabled = DEFAULT_ENABLED;

        private String serviceIdRegex;

        private String uriRegex;

        private Pattern serviceIdPattern;

        private Pattern uriPattern;

        private String scope;

        private Duration advancedExpiration = DEFAULT_ADVANCED_EXPIRATION;

        private HeaderTokenPropagatorConfigurationProperties headerPropagation;

        private Map<String, String> additonalRequestParams = Collections.emptyMap();

        @NonNull
        @Override
        public Duration getAdvancedExpiration() {
            return advancedExpiration;
        }

        @Override
        @NonNull
        public Optional<ClientCredentialsHeaderTokenPropagatorConfiguration> getHeaderPropagation() {
            return Optional.ofNullable(headerPropagation);
        }

        /**
         * Sets the Http Header Client Credentials Token Propagator configuration.
         *
         * @param headerPropagation client credentials header propagation.
         */
        public void setHeaderPropagation(@NonNull HeaderTokenPropagatorConfigurationProperties headerPropagation) {
            this.headerPropagation = headerPropagation;
        }

        /**
         * @param advancedExpiration Number of seconds for a token obtained via client credentials grant to be considered expired
         *                           prior to its expiration date. Default value (30 seconds).
         */
        public void setAdvancedExpiration(@NonNull Duration advancedExpiration) {
            this.advancedExpiration = advancedExpiration;
        }

        /**
         * @return a regular expression to match the service.
         */
        public String getServiceIdRegex() {
            return this.serviceIdRegex;
        }

        /**
         * @param serviceIdRegex A regular expression to match the service id.
         */
        public void setServiceIdRegex(String serviceIdRegex) {
            this.serviceIdRegex = serviceIdRegex;
        }

        /**
         * @return a regular expression to match the uri.
         */
        public String getUriRegex() {
            return this.uriRegex;
        }

        /**
         * @param uriRegex A regular expression to match the URI.
         */
        public void setUriRegex(String uriRegex) {
            this.uriRegex = uriRegex;
        }

        @Override
        public Pattern getServiceIdPattern() {
            if (this.serviceIdPattern == null && this.serviceIdRegex != null) {
                serviceIdPattern = Pattern.compile(this.serviceIdRegex);
            }
            return serviceIdPattern;
        }

        @Override
        public Pattern getUriPattern() {
            if (this.uriPattern == null && this.uriRegex != null) {
                uriPattern = Pattern.compile(this.uriRegex);
            }
            return uriPattern;
        }

        @NonNull
        @Override
        public Optional<String> getScope() {
            return Optional.ofNullable(scope);
        }

        /**
         * Scope to be requested in the client credentials request. Defaults to none.
         * @param scope Scope to be requested in the client credentials request
         */
        public void setScope(String scope) {
            this.scope = scope;
        }

        @Override
        public boolean isEnabled() {
            return enabled;
        }

        /**
         * Enables {@link io.micronaut.security.oauth2.client.clientcredentials.ClientCredentialsClient}. Default value {@value #DEFAULT_ENABLED}
         * @param enabled enabled flag
         */
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        /**
         * Client credentials http header token propagation configuration.
         */
        @ConfigurationProperties("header-propagation")
        public static class HeaderTokenPropagatorConfigurationProperties implements ClientCredentialsHeaderTokenPropagatorConfiguration {

            private String prefix = DEFAULT_PREFIX;
            private String headerName = DEFAULT_HEADER_NAME;
            private boolean enabled = DEFAULT_ENABLED;

            @Override
            public boolean isEnabled() {
                return enabled;
            }

            /**
             * Enable {@link ClientCredentialsHeaderTokenPropagatorConfiguration}. Default value ({@value #DEFAULT_ENABLED}).
             * @param enabled enabled flag
             */
            public void setEnabled(boolean enabled) {
                this.enabled = enabled;
            }

            /**
             * Value prefix for Http Header. Default value ({@value #DEFAULT_PREFIX}).
             * @param prefix preffix before the header value
             */
            public void setPrefix(String prefix) {
                this.prefix = prefix;
            }

            /**
             *
             * @return a Prefix before the token in the header value. E.g. Bearer
             */
            @Override
            public String getPrefix() {
                return this.prefix;
            }

            /**
             * Http Header to be used to propagate the token. Default value ({@value #DEFAULT_HEADER_NAME})
             * @param headerName HTTP header name
             */
            public void setHeaderName(String headerName) {
                this.headerName = headerName;
            }

            /**
             *
             * @return an HTTP Header name. e.g. Authorization
             */
            @Override
            public String getHeaderName() {
                return this.headerName;
            }

        }

        /**
         *
         * @return a Map of additional request parameters
         */
        @Override
        @NonNull
        public Map<String, String> getAdditionalRequestParams() {
            return additonalRequestParams;
        }

        /**
         * Additional parameters included in the client-credentials flow
         * @param additionalRequestParams Map of additional request parameters to include in client-credentials flow
         */
        public void setAdditionalRequestParams(@MapFormat(transformation = MapFormat.MapTransformation.FLAT) Map<String, String> additionalRequestParams) {
            this.additonalRequestParams = additionalRequestParams;
        }
    }

    /**
     * OAuth 2.0 authorization endpoint configuration.
     */
    @ConfigurationProperties("authorization")
    public static class AuthorizationEndpointConfigurationProperties extends DefaultEndpointConfiguration {

    }

    /**
     * OAuth 2.0 token endpoint configuration.
     */
    @ConfigurationProperties("token")
    public static class TokenEndpointConfigurationProperties extends DefaultSecureEndpointConfiguration {

    }

    /**
     * Introspection endpoint configuration.
     */
    @ConfigurationProperties("introspection")
    public static class IntrospectionEndpointConfigurationProperties extends DefaultSecureEndpointConfiguration implements IntrospectionEndpointConfiguration { }

    /**
     * Revocation endpoint configuration.
     */
    @ConfigurationProperties("revocation")
    public static class RevocationEndpointConfigurationProperties extends DefaultSecureEndpointConfiguration implements RevocationEndpointConfiguration { }

    /**
     * OpenID client configuration.
     */
    @ConfigurationProperties("openid")
    public static class OpenIdClientConfigurationProperties implements OpenIdClientConfiguration {

        private static final String DEFAULT_CONFIG_PATH = "/.well-known/openid-configuration";
        private final String name;

        private URL issuer;
        private String configurationPath = DEFAULT_CONFIG_PATH;
        private String jwksUri;
        private RegistrationEndpointConfigurationProperties registration;
        private UserInfoEndpointConfigurationProperties userInfo;
        private AuthorizationEndpointConfigurationProperties authorization;
        private TokenEndpointConfigurationProperties token;
        private EndSessionConfigurationProperties endSession = new EndSessionConfigurationProperties();

        /**
         * @param name The provider name
         */
        OpenIdClientConfigurationProperties(@Parameter String name) {
            this.name = name;
        }

        @NonNull
        @Override
        public String getName() {
            return name;
        }

        @Override
        public Optional<URL> getIssuer() {
            return Optional.ofNullable(issuer);
        }

        /**
         * URL using the https scheme with no query or fragment component that the
         * Open ID provider asserts as its issuer identifier.
         *
         * @param issuer The issuer
         */
        public void setIssuer(@Nullable URL issuer) {
            this.issuer = issuer;
        }

        @Override
        @NonNull
        public String getConfigurationPath() {
            return configurationPath;
        }

        /**
         * The configuration path to discover openid configuration. Default ({@value #DEFAULT_CONFIG_PATH}).
         *
         * @param configurationPath The configuration path
         */
        public void setConfigurationPath(@NonNull String configurationPath) {
            this.configurationPath = configurationPath;
        }

        @Override
        public Optional<String> getJwksUri() {
            return Optional.ofNullable(jwksUri);
        }

        /**
         * The JWKS signature URI.
         *
         * @param jwksUri The signature uri
         */
        public void setJwksUri(String jwksUri) {
            this.jwksUri = jwksUri;
        }

        @Override
        public Optional<EndpointConfiguration> getRegistration() {
            return Optional.ofNullable(registration);
        }

        /**
         * Sets the registration endpoint configuration.
         *
         * @param registration The registration endpoint configuration
         */
        public void setRegistration(RegistrationEndpointConfigurationProperties registration) {
            this.registration = registration;
        }

        @Override
        public Optional<EndpointConfiguration> getUserInfo() {
            return Optional.ofNullable(userInfo);
        }

        /**
         * Sets the user info endpoint configuration.
         *
         * @param userInfo The user info endpoint configuration
         */
        public void setUserInfo(UserInfoEndpointConfigurationProperties userInfo) {
            this.userInfo = userInfo;
        }

        @Override
        public Optional<AuthorizationEndpointConfiguration> getAuthorization() {
            return Optional.ofNullable(authorization);
        }

        /**
         * Sets the authorization endpoint configuration.
         *
         * @param authorization The authorization endpoint configuration
         */
        public void setAuthorization(AuthorizationEndpointConfigurationProperties authorization) {
            this.authorization = authorization;
        }

        @Override
        public Optional<TokenEndpointConfiguration> getToken() {
            return Optional.ofNullable(token);
        }

        /**
         * Sets the token endpoint configuration.
         *
         * @param token The token endpoint configuration
         */
        public void setToken(TokenEndpointConfigurationProperties token) {
            this.token = token;
        }

        @Override
        @NonNull
        public EndSessionEndpointConfiguration getEndSession() {
            return endSession;
        }

        /**
         * Sets the end session endpoint configuration.
         *
         * @param endSession End session endpoint configuration
         */
        public void setEndSession(@NonNull EndSessionConfigurationProperties endSession) {
            this.endSession = endSession;
        }

        /**
         * Registration endpoint configuration.
         */
        @ConfigurationProperties("registration")
        public static class RegistrationEndpointConfigurationProperties extends DefaultEndpointConfiguration { }

        /**
         * User info endpoint configuration.
         */
        @ConfigurationProperties("user-info")
        public static class UserInfoEndpointConfigurationProperties extends DefaultEndpointConfiguration { }

        /**
         * Authorization endpoint configuration.
         */
        @ConfigurationProperties("authorization")
        public static class AuthorizationEndpointConfigurationProperties extends DefaultEndpointConfiguration implements AuthorizationEndpointConfiguration {

            private ResponseType responseType = ResponseType.CODE;
            private String responseMode;
            private Display display;
            private Prompt prompt;
            private Integer maxAge;
            private List<String> uiLocales;
            private List<String>  acrValues;

            @NonNull
            @Override
            public ResponseType getResponseType() {
                return responseType;
            }

            /**
             * Determines the authorization processing flow to be used. Default value (code).
             *
             * @param responseType The response type
             */
            public void setResponseType(@NonNull ResponseType responseType) {
                this.responseType = responseType;
            }

            @Override
            public Optional<String> getResponseMode() {
                return Optional.ofNullable(responseMode);
            }

            /**
             * Mechanism to be used for returning authorization response parameters from the
             * authorization endpoint.
             *
             * @param responseMode The response mode
             */
            public void setResponseMode(@Nullable String responseMode) {
                this.responseMode = responseMode;
            }

            @Override
            public Optional<Display> getDisplay() {
                return Optional.ofNullable(display);
            }

            /**
             * Controls how the authentication interface is displayed.
             *
             * @param display The display
             */
            public void setDisplay(@Nullable Display display) {
                this.display = display;
            }

            @Override
            public Optional<Prompt> getPrompt() {
                return Optional.ofNullable(prompt);
            }

            /**
             * Controls how the authentication server prompts the user.
             *
             * @param prompt The prompt type
             */
            public void setPrompt(@Nullable Prompt prompt) {
                this.prompt = prompt;
            }

            @Override
            public Optional<Integer> getMaxAge() {
                return Optional.ofNullable(maxAge);
            }

            /**
             * Maximum authentication age.
             *
             * @param maxAge Maximum authentication age.
             */
            public void setMaxAge(@Nullable Integer maxAge) {
                this.maxAge = maxAge;
            }

            @Override
            public Optional<List<String>> getUiLocales() {
                return Optional.ofNullable(uiLocales);
            }

            /**
             * Preferred locales for authentication.
             *
             * @param uiLocales Preferred locales
             */
            public void setUiLocales(@Nullable List<String> uiLocales) {
                this.uiLocales = uiLocales;
            }

            @Override
            public Optional<List<String>> getAcrValues() {
                return Optional.ofNullable(acrValues);
            }

            /**
             * Authentication class reference values.
             *
             * @param acrValues Authentication class reference values
             */
            public void setAcrValues(@Nullable List<String>  acrValues) {
                this.acrValues = acrValues;
            }
        }

        /**
         * Token endpoint configuration.
         */
        @ConfigurationProperties("token")
        public static class TokenEndpointConfigurationProperties extends DefaultSecureEndpointConfiguration implements TokenEndpointConfiguration {
            private static final MediaType DEFAULT_CONTENT_TYPE = MediaType.APPLICATION_FORM_URLENCODED_TYPE;
            private MediaType contentType = DEFAULT_CONTENT_TYPE;

            @NonNull
            @Override
            public MediaType getContentType() {
                return this.contentType;
            }

            /**
             * The content type of token endpoint requests. Default value (application/x-www-form-urlencoded).
             *
             * @param contentType The content type
             */
            public void setContentType(@NonNull MediaType contentType) {
                this.contentType = contentType;
            }
        }

        /**
         * End session endpoint configuration.
         */
        @ConfigurationProperties("end-session")
        public static class EndSessionConfigurationProperties extends DefaultEndpointConfiguration implements EndSessionEndpointConfiguration {

            private static final boolean DEFAULT_ENABLED = true;
            private boolean enabled = DEFAULT_ENABLED;

            @Override
            public boolean isEnabled() {
                return enabled;
            }

            /**
             * The end session enabled flag. Default value ({@value #DEFAULT_ENABLED}).
             *
             * @param enabled The enabled flag
             */
            public void setEnabled(boolean enabled) {
                this.enabled = enabled;
            }
        }
    }
}
