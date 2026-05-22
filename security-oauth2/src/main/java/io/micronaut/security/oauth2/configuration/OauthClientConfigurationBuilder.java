/*
 * Copyright 2017-2025 original authors
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

import io.micronaut.http.MediaType;
import io.micronaut.security.oauth2.client.clientcredentials.ClientCredentialsConfiguration;
import io.micronaut.security.oauth2.client.clientcredentials.propagation.ClientCredentialsHeaderTokenPropagatorConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.OauthAuthorizationEndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.SecureEndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.TokenEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.endsession.request.AuthorizationServer;
import io.micronaut.security.oauth2.grants.GrantType;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Builder for programmatic {@link OauthClientConfiguration} instances.
 *
 * @since 5.1.0
 */
public final class OauthClientConfigurationBuilder {

    private @Nullable String name;
    private @Nullable String clientId;
    private @Nullable String clientSecret;
    private List<String> scopes = Collections.emptyList();
    private boolean enabled = true;
    private GrantType grantType = GrantType.AUTHORIZATION_CODE;
    private @Nullable SecureEndpointConfiguration token;
    private @Nullable OauthAuthorizationEndpointConfiguration authorization;
    private @Nullable ClientCredentialsConfiguration clientCredentials;
    private @Nullable SecureEndpointConfiguration introspection;
    private @Nullable SecureEndpointConfiguration revocation;
    private @Nullable OpenIdClientConfiguration openid;
    private @Nullable AuthorizationServer authorizationServer;
    private boolean proxyWellKnownOauthAuthorizationServer;
    private boolean proxyWellKnownOpenidConfiguration;

    /**
     * @return A new OAuth client configuration builder.
     */
    @NonNull
    public static OauthClientConfigurationBuilder builder() {
        return new OauthClientConfigurationBuilder();
    }

    /**
     * Sets the OAuth client configuration name.
     *
     * @param name The OAuth client configuration name.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder name(@NonNull String name) {
        this.name = Objects.requireNonNull(name, "name");
        return this;
    }

    /**
     * Sets the OAuth client identifier.
     *
     * @param clientId The OAuth client identifier.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder clientId(@NonNull String clientId) {
        this.clientId = Objects.requireNonNull(clientId, "clientId");
        return this;
    }

    /**
     * Sets the OAuth client secret.
     *
     * @param clientSecret The OAuth client secret.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder clientSecret(@Nullable String clientSecret) {
        this.clientSecret = clientSecret;
        return this;
    }

    /**
     * Sets the requested scopes for the OAuth client.
     *
     * @param scopes The requested scopes.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder scopes(@NonNull List<String> scopes) {
        this.scopes = List.copyOf(Objects.requireNonNull(scopes, "scopes"));
        return this;
    }

    /**
     * Sets the requested scopes for the OAuth client.
     *
     * @param scopes The requested scopes.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder scopes(@NonNull String... scopes) {
        this.scopes = List.of(Objects.requireNonNull(scopes, "scopes"));
        return this;
    }

    /**
     * Sets whether the OAuth client configuration is enabled.
     *
     * @param enabled Whether the OAuth client configuration is enabled.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder enabled(boolean enabled) {
        this.enabled = enabled;
        return this;
    }

    /**
     * Sets the OAuth grant type.
     *
     * @param grantType The OAuth grant type.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder grantType(@NonNull GrantType grantType) {
        this.grantType = Objects.requireNonNull(grantType, "grantType");
        return this;
    }

    /**
     * Sets the token endpoint configuration.
     *
     * @param token The token endpoint configuration.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder token(@NonNull SecureEndpointConfiguration token) {
        this.token = Objects.requireNonNull(token, "token");
        return this;
    }

    /**
     * Sets the token endpoint URL.
     *
     * @param url The token endpoint URL.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder token(@NonNull String url) {
        return token(url, null);
    }

    /**
     * Sets the token endpoint URL and authentication method.
     *
     * @param url The token endpoint URL.
     * @param authenticationMethod The token endpoint authentication method.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder token(@NonNull String url, @Nullable String authenticationMethod) {
        return token(url, authenticationMethod, MediaType.APPLICATION_FORM_URLENCODED_TYPE);
    }

    /**
     * Sets the token endpoint URL, authentication method, and content type.
     *
     * @param url The token endpoint URL.
     * @param authenticationMethod The token endpoint authentication method.
     * @param contentType The token endpoint request content type.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder token(@NonNull String url,
                                                 @Nullable String authenticationMethod,
                                                 @NonNull MediaType contentType) {
        this.token = new DefaultTokenEndpointConfiguration(url, authenticationMethod, contentType);
        return this;
    }

    /**
     * Sets the authorization endpoint configuration.
     *
     * @param authorization The authorization endpoint configuration.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder authorization(@NonNull OauthAuthorizationEndpointConfiguration authorization) {
        this.authorization = Objects.requireNonNull(authorization, "authorization");
        return this;
    }

    /**
     * Sets the authorization endpoint URL.
     *
     * @param url The authorization endpoint URL.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder authorization(@NonNull String url) {
        return authorization(url, null);
    }

    /**
     * Sets the authorization endpoint URL and PKCE code challenge method.
     *
     * @param url The authorization endpoint URL.
     * @param codeChallengeMethod The PKCE code challenge method.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder authorization(@NonNull String url, @Nullable String codeChallengeMethod) {
        this.authorization = new DefaultAuthorizationEndpointConfiguration(url, codeChallengeMethod);
        return this;
    }

    /**
     * Sets the client credentials configuration and selects the client credentials grant.
     *
     * @param clientCredentials The client credentials configuration.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder clientCredentialsConfiguration(@NonNull ClientCredentialsConfiguration clientCredentials) {
        this.clientCredentials = Objects.requireNonNull(clientCredentials, "clientCredentials");
        this.grantType = GrantType.CLIENT_CREDENTIALS;
        return this;
    }

    /**
     * Enables client credentials support without requesting a scope.
     *
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder clientCredentials() {
        return clientCredentials((String) null);
    }

    /**
     * Enables client credentials support with the supplied scope.
     *
     * @param scope The client credentials scope.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder clientCredentials(@Nullable String scope) {
        return clientCredentials(scope, OauthClientConfiguration.DEFAULT_ADVANCED_EXPIRATION);
    }

    /**
     * Enables client credentials support with the supplied scope and advanced expiration.
     *
     * @param scope The client credentials scope.
     * @param advancedExpiration The duration before token expiry to consider the token expired.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder clientCredentials(@Nullable String scope, @NonNull Duration advancedExpiration) {
        return clientCredentials(scope, advancedExpiration, Collections.emptyMap());
    }

    /**
     * Enables client credentials support with additional token request parameters.
     *
     * @param scope The client credentials scope.
     * @param advancedExpiration The duration before token expiry to consider the token expired.
     * @param additionalRequestParams Additional request parameters for the token request.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder clientCredentials(@Nullable String scope,
                                                            @NonNull Duration advancedExpiration,
                                                            @NonNull Map<String, String> additionalRequestParams) {
        return clientCredentialsConfiguration(new DefaultClientCredentialsConfiguration(
            true,
            scope,
            advancedExpiration,
            null,
            additionalRequestParams,
            null,
            null
        ));
    }

    /**
     * Sets the token introspection endpoint configuration.
     *
     * @param introspection The token introspection endpoint configuration.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder introspection(@NonNull SecureEndpointConfiguration introspection) {
        this.introspection = Objects.requireNonNull(introspection, "introspection");
        return this;
    }

    /**
     * Sets the token introspection endpoint URL.
     *
     * @param url The token introspection endpoint URL.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder introspection(@NonNull String url) {
        return introspection(url, null);
    }

    /**
     * Sets the token introspection endpoint URL and authentication method.
     *
     * @param url The token introspection endpoint URL.
     * @param authenticationMethod The introspection endpoint authentication method.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder introspection(@NonNull String url, @Nullable String authenticationMethod) {
        this.introspection = new DefaultSecureEndpointConfiguration(url, authenticationMethod);
        return this;
    }

    /**
     * Sets the token revocation endpoint configuration.
     *
     * @param revocation The token revocation endpoint configuration.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder revocation(@NonNull SecureEndpointConfiguration revocation) {
        this.revocation = Objects.requireNonNull(revocation, "revocation");
        return this;
    }

    /**
     * Sets the token revocation endpoint URL.
     *
     * @param url The token revocation endpoint URL.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder revocation(@NonNull String url) {
        return revocation(url, null);
    }

    /**
     * Sets the token revocation endpoint URL and authentication method.
     *
     * @param url The token revocation endpoint URL.
     * @param authenticationMethod The revocation endpoint authentication method.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder revocation(@NonNull String url, @Nullable String authenticationMethod) {
        this.revocation = new DefaultSecureEndpointConfiguration(url, authenticationMethod);
        return this;
    }

    /**
     * Sets the OpenID client configuration.
     *
     * @param openid The OpenID client configuration.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder openid(@NonNull OpenIdClientConfiguration openid) {
        this.openid = Objects.requireNonNull(openid, "openid");
        return this;
    }

    /**
     * Sets the authorization server type.
     *
     * @param authorizationServer The authorization server type.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder authorizationServer(@Nullable AuthorizationServer authorizationServer) {
        this.authorizationServer = authorizationServer;
        return this;
    }

    /**
     * Sets whether the OAuth authorization server metadata endpoint is proxied.
     *
     * @param proxyWellKnownOauthAuthorizationServer Whether to proxy OAuth authorization server metadata.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder proxyWellKnownOauthAuthorizationServer(boolean proxyWellKnownOauthAuthorizationServer) {
        this.proxyWellKnownOauthAuthorizationServer = proxyWellKnownOauthAuthorizationServer;
        return this;
    }

    /**
     * Sets whether the OpenID provider metadata endpoint is proxied.
     *
     * @param proxyWellKnownOpenidConfiguration Whether to proxy OpenID provider metadata.
     * @return This builder.
     */
    @NonNull
    public OauthClientConfigurationBuilder proxyWellKnownOpenidConfiguration(boolean proxyWellKnownOpenidConfiguration) {
        this.proxyWellKnownOpenidConfiguration = proxyWellKnownOpenidConfiguration;
        return this;
    }

    /**
     * Builds the OAuth client configuration.
     *
     * @return The OAuth client configuration.
     */
    @NonNull
    public OauthClientConfiguration build() {
        return new DefaultOauthClientConfiguration(this);
    }

    private static final class DefaultOauthClientConfiguration implements OauthClientConfiguration {
        private final String name;
        private final String clientId;
        private final @Nullable String clientSecret;
        private final List<String> scopes;
        private final boolean enabled;
        private final GrantType grantType;
        private final @Nullable SecureEndpointConfiguration token;
        private final @Nullable OauthAuthorizationEndpointConfiguration authorization;
        private final @Nullable ClientCredentialsConfiguration clientCredentials;
        private final @Nullable SecureEndpointConfiguration introspection;
        private final @Nullable SecureEndpointConfiguration revocation;
        private final @Nullable OpenIdClientConfiguration openid;
        private final @Nullable AuthorizationServer authorizationServer;
        private final boolean proxyWellKnownOauthAuthorizationServer;
        private final boolean proxyWellKnownOpenidConfiguration;

        private DefaultOauthClientConfiguration(OauthClientConfigurationBuilder builder) {
            this.name = Objects.requireNonNull(builder.name, "name");
            this.clientId = Objects.requireNonNull(builder.clientId, "clientId");
            this.clientSecret = builder.clientSecret;
            this.scopes = List.copyOf(builder.scopes);
            this.enabled = builder.enabled;
            this.grantType = builder.grantType;
            this.token = builder.token;
            this.authorization = builder.authorization;
            this.clientCredentials = builder.clientCredentials;
            this.introspection = builder.introspection;
            this.revocation = builder.revocation;
            this.openid = builder.openid;
            this.authorizationServer = builder.authorizationServer;
            this.proxyWellKnownOauthAuthorizationServer = builder.proxyWellKnownOauthAuthorizationServer;
            this.proxyWellKnownOpenidConfiguration = builder.proxyWellKnownOpenidConfiguration;
        }

        @Override
        public boolean isEnabled() {
            return enabled;
        }

        @Override
        @NonNull
        public String getName() {
            return name;
        }

        @Override
        @NonNull
        public String getClientId() {
            return clientId;
        }

        @Override
        @Nullable
        public String getClientSecret() {
            return clientSecret;
        }

        @Override
        @NonNull
        public List<String> getScopes() {
            return scopes;
        }

        @Override
        @NonNull
        public GrantType getGrantType() {
            return grantType;
        }

        @Override
        public Optional<SecureEndpointConfiguration> getToken() {
            return Optional.ofNullable(token);
        }

        @Override
        public Optional<OauthAuthorizationEndpointConfiguration> getAuthorization() {
            return Optional.ofNullable(authorization);
        }

        @Override
        @NonNull
        public Optional<ClientCredentialsConfiguration> getClientCredentials() {
            return Optional.ofNullable(clientCredentials);
        }

        @Override
        public Optional<SecureEndpointConfiguration> getIntrospection() {
            return Optional.ofNullable(introspection);
        }

        @Override
        public Optional<SecureEndpointConfiguration> getRevocation() {
            return Optional.ofNullable(revocation);
        }

        @Override
        public Optional<OpenIdClientConfiguration> getOpenid() {
            return Optional.ofNullable(openid);
        }

        @Override
        @Nullable
        public AuthorizationServer getAuthorizationServer() {
            return authorizationServer;
        }

        @Override
        public boolean isProxyWellKnownOauthAuthorizationServer() {
            return proxyWellKnownOauthAuthorizationServer;
        }

        @Override
        public boolean isProxyWellKnownOpenidConfiguration() {
            return proxyWellKnownOpenidConfiguration;
        }
    }

    private static class DefaultSecureEndpointConfiguration implements SecureEndpointConfiguration {
        private final String url;
        private final @Nullable String authenticationMethod;

        private DefaultSecureEndpointConfiguration(String url, @Nullable String authenticationMethod) {
            this.url = Objects.requireNonNull(url, "url");
            this.authenticationMethod = authenticationMethod;
        }

        @Override
        public Optional<String> getUrl() {
            return Optional.of(url);
        }

        @Override
        public Optional<String> getAuthenticationMethod() {
            return Optional.ofNullable(authenticationMethod);
        }
    }

    private static final class DefaultTokenEndpointConfiguration extends DefaultSecureEndpointConfiguration implements TokenEndpointConfiguration {
        private final MediaType contentType;

        private DefaultTokenEndpointConfiguration(String url,
                                                  @Nullable String authenticationMethod,
                                                  MediaType contentType) {
            super(url, authenticationMethod);
            this.contentType = Objects.requireNonNull(contentType, "contentType");
        }

        @Override
        @NonNull
        public MediaType getContentType() {
            return contentType;
        }
    }

    private static final class DefaultAuthorizationEndpointConfiguration implements OauthAuthorizationEndpointConfiguration {
        private final String url;
        private final @Nullable String codeChallengeMethod;

        private DefaultAuthorizationEndpointConfiguration(String url, @Nullable String codeChallengeMethod) {
            this.url = Objects.requireNonNull(url, "url");
            this.codeChallengeMethod = codeChallengeMethod;
        }

        @Override
        public Optional<String> getUrl() {
            return Optional.of(url);
        }

        @Override
        @NonNull
        public Optional<String> getCodeChallengeMethod() {
            return Optional.ofNullable(codeChallengeMethod);
        }
    }

    private static final class DefaultClientCredentialsConfiguration implements ClientCredentialsConfiguration {
        private final boolean enabled;
        private final @Nullable String scope;
        private final Duration advancedExpiration;
        private final @Nullable ClientCredentialsHeaderTokenPropagatorConfiguration headerPropagation;
        private final Map<String, String> additionalRequestParams;
        private final @Nullable Pattern serviceIdPattern;
        private final @Nullable Pattern uriPattern;

        private DefaultClientCredentialsConfiguration(boolean enabled,
                                                      @Nullable String scope,
                                                      Duration advancedExpiration,
                                                      @Nullable ClientCredentialsHeaderTokenPropagatorConfiguration headerPropagation,
                                                      Map<String, String> additionalRequestParams,
                                                      @Nullable String serviceIdRegex,
                                                      @Nullable String uriRegex) {
            this.enabled = enabled;
            this.scope = scope;
            this.advancedExpiration = Objects.requireNonNull(advancedExpiration, "advancedExpiration");
            this.headerPropagation = headerPropagation;
            this.additionalRequestParams = Map.copyOf(Objects.requireNonNull(additionalRequestParams, "additionalRequestParams"));
            this.serviceIdPattern = serviceIdRegex == null ? null : Pattern.compile(serviceIdRegex);
            this.uriPattern = uriRegex == null ? null : Pattern.compile(uriRegex);
        }

        @Override
        public boolean isEnabled() {
            return enabled;
        }

        @Override
        @NonNull
        public Optional<String> getScope() {
            return Optional.ofNullable(scope);
        }

        @Override
        @NonNull
        public Duration getAdvancedExpiration() {
            return advancedExpiration;
        }

        @Override
        @NonNull
        public Optional<ClientCredentialsHeaderTokenPropagatorConfiguration> getHeaderPropagation() {
            return Optional.ofNullable(headerPropagation);
        }

        @Override
        @NonNull
        public Map<String, String> getAdditionalRequestParams() {
            return additionalRequestParams;
        }

        @Override
        @Nullable
        public Pattern getServiceIdPattern() {
            return serviceIdPattern;
        }

        @Override
        @Nullable
        public Pattern getUriPattern() {
            return uriPattern;
        }
    }
}
