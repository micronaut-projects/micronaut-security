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

package io.micronaut.security.oauth2.openid.configuration;

import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Requires;
import io.micronaut.security.oauth2.openid.endpoints.OpenIdEndpoints;
import io.micronaut.security.oauth2.openid.endpoints.authorization.AuthorizationEndpointConfiguration;
import io.micronaut.security.oauth2.openid.endpoints.endsession.EndSessionEndpointConfiguration;
import io.micronaut.security.oauth2.openid.endpoints.introspection.IntrospectionEndpointConfiguration;
import io.micronaut.security.oauth2.openid.endpoints.registration.RegistrationEndpointConfiguration;
import io.micronaut.security.oauth2.openid.endpoints.revocation.RevocationEndpointConfiguration;
import io.micronaut.security.oauth2.openid.endpoints.token.TokenEndpointConfiguration;
import io.micronaut.security.oauth2.openid.endpoints.userinfo.UserInfoEndpointConfiguration;

import javax.annotation.Nullable;
import javax.inject.Singleton;

/**
 * Factory which creates beans of type Creates a HTTP Declarative client to communicate with an OpenID connect Discovery endpoint.
 * The discovery endpoint is declared by the property micronaut.security.oauth2.issuer
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Factory
public class OpenIdFactory {

    /**
     * @param openIdConfiguration OpenID configuration
     * @param endSessionEndpointConfiguration End-session endpoint configuration
     * @return a bean of type {@link OpenIdProviderMetadataSession}
     */
    @Singleton
    @Requires(beans = EndSessionEndpointConfiguration.class)
    public OpenIdProviderMetadataSession openIdProviderMetadataSession(@Nullable OpenIdConfiguration openIdConfiguration,
                                                                       EndSessionEndpointConfiguration endSessionEndpointConfiguration) {
        return new OpenIdProviderMetadataSessionAdapter(openIdConfiguration, endSessionEndpointConfiguration);
    }

    /**
     * @param openIdConfiguration OpenID configuration
     * @param openIdProviderConfiguration Open ID Provider configuration
     * @param authorizationEndpointConfiguration Authorization endpoint configuration
     * @param introspectionEndpointConfiguration Introspection endpoint configuration
     * @param registrationEndpointConfiguration Registration endpoint configuration
     * @param revocationEndpointConfiguration Revocation endpoint configuration
     * @param tokenEndpointConfiguration Token endpoint configuration
     * @param userInfoEndpointConfiguration User Info endpoint configuration
     * @return a bean of type {@link OpenIdProviderMetadata}
     */
    @Requires(beans = {OpenIdProviderConfiguration.class,
            AuthorizationEndpointConfiguration.class,
            IntrospectionEndpointConfiguration.class,
            RegistrationEndpointConfiguration.class,
            RevocationEndpointConfiguration.class,
            TokenEndpointConfiguration.class,
            UserInfoEndpointConfiguration.class})
    @Singleton
    public OpenIdProviderMetadata openIdProviderMetadata(@Nullable OpenIdConfiguration openIdConfiguration,
                                                         OpenIdProviderConfiguration openIdProviderConfiguration,
                                                         AuthorizationEndpointConfiguration authorizationEndpointConfiguration,
                                                         IntrospectionEndpointConfiguration introspectionEndpointConfiguration,
                                                         RegistrationEndpointConfiguration registrationEndpointConfiguration,
                                                         RevocationEndpointConfiguration revocationEndpointConfiguration,
                                                         TokenEndpointConfiguration tokenEndpointConfiguration,
                                                         UserInfoEndpointConfiguration userInfoEndpointConfiguration) {
        return new OpenIdProviderMetadataAdapter(openIdConfiguration,
                openIdProviderConfiguration,
                authorizationEndpointConfiguration,
                introspectionEndpointConfiguration,
                registrationEndpointConfiguration,
                revocationEndpointConfiguration,
                tokenEndpointConfiguration,
                userInfoEndpointConfiguration);
    }

    /**
     *
     * @param openIdProviderMetadata Open ID Provider metadata
     * @param openIdProviderMetadataSession Open ID Provider Metadata Session
     * @return a bean of type {@link OpenIdEndpoints}
     */
    @Singleton
    public OpenIdEndpoints openIdEndpoints(OpenIdProviderMetadata openIdProviderMetadata,
                                           OpenIdProviderMetadataSession openIdProviderMetadataSession) {
        return new OpenIdEndpointsAdapter(openIdProviderMetadata, openIdProviderMetadataSession);
    }

}
