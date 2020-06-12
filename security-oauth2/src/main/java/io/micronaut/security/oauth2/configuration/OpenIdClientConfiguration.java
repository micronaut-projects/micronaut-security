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

import io.micronaut.core.naming.Named;
import io.micronaut.security.oauth2.configuration.endpoints.*;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.net.URL;
import java.util.Optional;

/**
 * Configuration for an OpenID client.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
public interface OpenIdClientConfiguration extends Named {

    /**
     * @return URL that the OpenID provider asserts as its issuer identifier.
     */
    Optional<URL> getIssuer();

    /**
     * @return The OpenID configuration path
     */
    String getConfigurationPath();


    /**
     * @return The JWKS configuration
     */
    Optional<String> getJwksUri();

    /**
     * @see <a href="https://tools.ietf.org/html/rfc7591#section-3.1">RFC 7591 - Section 3.1</a>
     * @see <a href="https://openid.net/specs/openid-connect-registration-1_0.html#ClientRegistration">OpenID Connect Client Registration</a>
     * @return The registration endpoint configuration
     */
    Optional<EndpointConfiguration> getRegistration();

    /**
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">OpenID Connect Core 1.0 - UserInfo</a>
     * @return The user info endpoint configuration
     */
    Optional<EndpointConfiguration> getUserInfo();

    /**
     * @see <a href="https://tools.ietf.org/html/rfc6749#section-3.1">RFC 6749 - Section 3.1</a>
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint">OpenID Connect Core 1.0 - Authorization Endpoint</a>
     * @return The authorization endpoint configuration
     */
    Optional<AuthorizationEndpointConfiguration> getAuthorization();

    /**
     * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.1.3">RFC 6749 - Section 4.1.3</a>
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint">OpenID Connect Core 1.0</a>
     * @return The token endpoint configuration
     */
    Optional<TokenEndpointConfiguration> getToken();

    /**
     * @see <a href="https://openid.net/specs/openid-connect-session-1_0.html">OpenID Connect Session 1.0</a>
     * @return The end session configuration
     */
    @NonNull
    EndSessionEndpointConfiguration getEndSession();
}
