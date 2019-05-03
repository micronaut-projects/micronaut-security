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

import io.micronaut.core.naming.Named;
import io.micronaut.core.util.Toggleable;
import io.micronaut.security.oauth2.configuration.endpoints.SecureEndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.AuthorizationEndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.EndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.TokenEndpointConfiguration;

import javax.annotation.Nonnull;
import java.net.URL;
import java.util.Optional;

/**
 * Configuration for an OpenID Provider.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public interface OpenIdClientConfiguration extends Named {

    /**
     * @return URL using the https scheme with no query or fragment component that the Open ID Provider asserts as its Issuer Identifier.
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
     * https://tools.ietf.org/html/rfc7662.
     *
     * @return The introspection endpoint configuration
     */
    Optional<SecureEndpointConfiguration> getIntrospection();

    /**
     * https://tools.ietf.org/html/rfc7009.
     *
     * @return The revocation endpoint configuration
     */
    Optional<SecureEndpointConfiguration> getRevocation();

    /**
     * @return The registration endpoint configuration
     */
    Optional<EndpointConfiguration> getRegistration();

    /**
     * @return The user info endpoint configuration
     */
    Optional<EndpointConfiguration> getUserInfo();

    Optional<AuthorizationEndpointConfiguration> getAuthorization();

    Optional<TokenEndpointConfiguration> getToken();

    @Nonnull
    Toggleable getEndSession();
}
