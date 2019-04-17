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
import io.micronaut.security.oauth2.openid.endpoints.authorization.AuthorizationEndpoint;
import io.micronaut.security.oauth2.openid.endpoints.endsession.EndSessionEndpoint;
import io.micronaut.security.oauth2.openid.endpoints.introspection.IntrospectionEndpoint;
import io.micronaut.security.oauth2.openid.endpoints.registration.RegistrationEndpoint;
import io.micronaut.security.oauth2.openid.endpoints.revocation.RevocationEndpoint;
import io.micronaut.security.oauth2.openid.endpoints.token.TokenEndpoint;
import io.micronaut.security.oauth2.openid.endpoints.userinfo.UserInfoEndpoint;

import javax.annotation.Nullable;
import javax.inject.Singleton;

/**
 * Factory which creates beans of type Creates a HTTP Declarative client to communicate with an OpenID connect Discovery endpoint.
 * The discovery endpoint is declared by the property micronaut.security.oauth2.openid.issuer
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Factory
public class OpenIdFactory {

    /**
     * @param openIdConfiguration OpenID configuration
     * @param endSessionEndpoint End-session endpoint configuration
     * @return a bean of type {@link OpenIdProviderMetadataSession}
     */
    @Singleton
    @Requires(beans = EndSessionEndpoint.class)
    public OpenIdProviderMetadataSession openIdProviderMetadataSession(@Nullable OpenIdConfiguration openIdConfiguration,
                                                                       EndSessionEndpoint endSessionEndpoint) {
        return new OpenIdProviderMetadataSessionAdapter(openIdConfiguration, endSessionEndpoint);
    }

    /**
     * @param openIdConfiguration OpenID configuration
     * @param openIdProviderConfiguration Open ID Provider configuration
     * @param authorizationEndpoint Authorization endpoint configuration
     * @param introspectionEndpoint Introspection endpoint configuration
     * @param registrationEndpoint Registration endpoint configuration
     * @param revocationEndpoint Revocation endpoint configuration
     * @param tokenEndpoint Token endpoint configuration
     * @param userInfoEndpoint User Info endpoint configuration
     * @return a bean of type {@link OpenIdProviderMetadata}
     */
    @Requires(beans = {OpenIdProviderConfiguration.class,
            AuthorizationEndpoint.class,
            IntrospectionEndpoint.class,
            RegistrationEndpoint.class,
            RevocationEndpoint.class,
            TokenEndpoint.class,
            UserInfoEndpoint.class})
    @Singleton
    public OpenIdProviderMetadata openIdProviderMetadata(@Nullable OpenIdConfiguration openIdConfiguration,
                                                         OpenIdProviderConfiguration openIdProviderConfiguration,
                                                         AuthorizationEndpoint authorizationEndpoint,
                                                         IntrospectionEndpoint introspectionEndpoint,
                                                         RegistrationEndpoint registrationEndpoint,
                                                         RevocationEndpoint revocationEndpoint,
                                                         TokenEndpoint tokenEndpoint,
                                                         UserInfoEndpoint userInfoEndpoint) {
        return new OpenIdProviderMetadataAdapter(openIdConfiguration,
                openIdProviderConfiguration,
                authorizationEndpoint,
                introspectionEndpoint,
                registrationEndpoint,
                revocationEndpoint,
                tokenEndpoint,
                userInfoEndpoint);
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
