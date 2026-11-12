/*
 * Copyright 2017-2023 original authors
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

import io.micronaut.context.exceptions.ConfigurationException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.core.util.Toggleable;
import io.micronaut.security.oauth2.client.clientcredentials.ClientCredentialsConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.OauthAuthorizationEndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.SecureEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethods;
import io.micronaut.security.oauth2.endpoint.DefaultSecureEndpoint;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.endsession.request.AuthorizationServer;
import io.micronaut.security.oauth2.grants.GrantType;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * OAuth 2.0 client configuration.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
public interface OauthClientConfiguration extends Toggleable {
    String DEFAULT_AUTH_METHOD = AuthenticationMethods.CLIENT_SECRET_POST;

    /**
     * The default advanced expiration value for client credentials grant.
     */
    Duration DEFAULT_ADVANCED_EXPIRATION = Duration.ofSeconds(30);

    /**
     * @return The provider name
     */
    @NonNull
    String getName();

    /**
     * @return The client id
     */
    @NonNull
    String getClientId();

    /**
     * @return The client secret
     */
    @Nullable
    String getClientSecret();

    /**
     * @return The scopes requested
     */
    @NonNull
    List<String> getScopes();

    /**
     * @return The grant type
     */
    @NonNull
    GrantType getGrantType();

    /**
     * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.1.3">RFC 6749 Section 4.1.3</a>
     * @return The optional token endpoint configuration
     */
    Optional<SecureEndpointConfiguration> getToken();

    /**
     * @see <a href="https://tools.ietf.org/html/rfc6749#section-3.1">RFC 6749 Section 3.1</a>
     * @return The optional authorization endpoint configuration
     */
    Optional<OauthAuthorizationEndpointConfiguration> getAuthorization();

    /**
     *
     * @return The Client Credentials Configuration
     */
    @NonNull
    Optional<ClientCredentialsConfiguration> getClientCredentials();

    /**
     * @see <a href="https://tools.ietf.org/html/rfc7662">RFC 7662</a>
     * @return The introspection endpoint configuration
     */
    Optional<SecureEndpointConfiguration> getIntrospection();

    /**
     * @see <a href="https://tools.ietf.org/html/rfc7009">RFC 7009</a>
     * @return The revocation endpoint configuration
     */
    Optional<SecureEndpointConfiguration> getRevocation();

    /**
     * @return The optional OpenID configuration
     */
    Optional<OpenIdClientConfiguration> getOpenid();

    /**
     *
     * @return The Token endpoint
     * @throws ConfigurationException if token endpoint url is not set in configuration
     */
    default SecureEndpoint getTokenEndpoint() throws ConfigurationException {
        return getToken().map(secureEndpointConfiguration -> new DefaultSecureEndpoint(secureEndpointConfiguration, DEFAULT_AUTH_METHOD))
                .orElseThrow(() -> new ConfigurationException("Oauth client "  + getName() + " requires the token endpoint configuration to be set in configuration"));
    }

    /**
     * @return The {@link AuthorizationServer} used by the OAuth Client.
     * @since 4.15.0
     */
    @Nullable
    default AuthorizationServer getAuthorizationServer() {
        return null;
    }

    /**
     *
     * @return Whether a request to /.well-known/oauth-authorization-server should be proxied to the authorization server.
     * @since 4.15.0
     */
    default boolean isProxyWellKnownOauthAuthorizationServer() {
        return false;
    }

    /**
     *
     * @return Whether a request to /.well-known/openid-configuration should be proxied to the authorization server.
     * @since 4.15.0
     */
    default boolean isProxyWellKnownOpenidConfiguration() {
        return false;
    }


    /**
     * @since 5.1.0
     * @return A new OAuth client configuration builder.
     */
    @NonNull
    static OauthClientConfigurationBuilder builder() {
        return new OauthClientConfigurationBuilder();
    }
}
