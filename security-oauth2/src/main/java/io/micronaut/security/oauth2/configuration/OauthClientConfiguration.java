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

import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.util.Toggleable;
import io.micronaut.security.oauth2.configuration.endpoints.EndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.SecureEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethod;
import io.micronaut.security.oauth2.endpoint.DefaultSecureEndpoint;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.grants.GrantType;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * OAuth 2.0 client configuration.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
public interface OauthClientConfiguration extends Toggleable {

    AuthenticationMethod DEFAULT_AUTHENTICATION_METHOD = AuthenticationMethod.CLIENT_SECRET_POST;

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
    Optional<EndpointConfiguration> getAuthorization();

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
        Optional<SecureEndpointConfiguration> tokenOptional = getToken();
        return new DefaultSecureEndpoint(tokenOptional.flatMap(EndpointConfiguration::getUrl)
                .orElseThrow(() -> new ConfigurationException("Oauth client requires the token endpoint URL to be set in configuration")),
                Collections.singletonList(tokenOptional.flatMap(SecureEndpointConfiguration::getAuthMethod)
                        .orElse(DEFAULT_AUTHENTICATION_METHOD)));
    }
}
