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

import io.micronaut.core.util.Toggleable;
import io.micronaut.security.oauth2.configuration.endpoints.EndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.SecureEndpointConfiguration;
import io.micronaut.security.oauth2.grants.GrantType;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;
import java.util.Optional;

/**
 * OAuth 2.0 client configuration.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
public interface OauthClientConfiguration extends Toggleable {

    /**
     * @return The provider name
     */
    @Nonnull
    String getName();

    /**
     * @return The client id
     */
    @Nonnull
    String getClientId();

    /**
     * @return The client secret
     */
    @Nullable
    String getClientSecret();

    /**
     * @return The scopes requested
     */
    @Nonnull
    List<String> getScopes();

    /**
     * @return The grant type
     */
    @Nonnull
    GrantType getGrantType();

    /**
     * https://tools.ietf.org/html/rfc6749#section-4.1.3
     *
     * @return The optional token endpoint configuration
     */
    Optional<SecureEndpointConfiguration> getToken();

    /**
     * https://tools.ietf.org/html/rfc6749#section-3.1
     *
     * @return The optional authorization endpoint configuration
     */
    Optional<EndpointConfiguration> getAuthorization();

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
     * @return The optional OpenID configuration
     */
    Optional<OpenIdClientConfiguration> getOpenid();
}
