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
     * @see https://tools.ietf.org/html/rfc7591#section-3.1
     * @see https://openid.net/specs/openid-connect-registration-1_0.html#ClientRegistration
     * @return The registration endpoint configuration
     */
    Optional<EndpointConfiguration> getRegistration();

    /**
     * @see https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
     * @return The user info endpoint configuration
     */
    Optional<EndpointConfiguration> getUserInfo();

    /**
     * @see https://tools.ietf.org/html/rfc6749#section-3.1
     * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint
     *
     * @return The authorization endpoint configuration
     */
    Optional<AuthorizationEndpointConfiguration> getAuthorization();

    /**
     * @see https://tools.ietf.org/html/rfc6749#section-4.1.3
     * @see https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
     * @return The token endpoint configuration
     */
    Optional<TokenEndpointConfiguration> getToken();

    /**
     * @see https://openid.net/specs/openid-connect-session-1_0.html
     * @return The end session configuration
     */
    @NonNull
    EndSessionEndpointConfiguration getEndSession();
}
