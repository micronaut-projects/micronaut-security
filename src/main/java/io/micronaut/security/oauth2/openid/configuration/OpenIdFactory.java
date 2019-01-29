/*
 * Copyright 2017-2018 original authors
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

import com.nimbusds.jose.jwk.KeyType;
import io.micronaut.context.annotation.Bean;
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
import io.micronaut.security.token.jwt.signature.jwks.JwksSignature;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.inject.Singleton;

/**
 * Factory which creates beans of type Creates a HTTP Declarative client to communicate with an OpenID connect Discovery endpoint.
 * The discovery endpoint is declared by the property micronaut.security.oauth2.openid-configuration
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
@Requires(beans = {OpenIdProviderConfiguration.class,
        AuthorizationEndpointConfiguration.class,
        EndSessionEndpointConfiguration.class,
        IntrospectionEndpointConfiguration.class,
        RegistrationEndpointConfiguration.class,
        RevocationEndpointConfiguration.class,
        TokenEndpointConfiguration.class,
        UserInfoEndpointConfiguration.class})
@Factory
public class OpenIdFactory {

    @Nullable
    private final OpenIdConfiguration openIdConfiguration;

    @Nonnull
    private final OpenIdProviderConfiguration openIdProviderConfiguration;

    @Nonnull
    private final EndSessionEndpointConfiguration endSessionEndpointConfiguration;

    @Nonnull
    private final AuthorizationEndpointConfiguration authorizationEndpointConfiguration;

    @Nonnull
    private final IntrospectionEndpointConfiguration introspectionEndpointConfiguration;

    @Nonnull
    private final RegistrationEndpointConfiguration registrationEndpointConfiguration;

    @Nonnull
    private final RevocationEndpointConfiguration revocationEndpointConfiguration;

    @Nonnull
    private final TokenEndpointConfiguration tokenEndpointConfiguration;

    @Nonnull
    private final UserInfoEndpointConfiguration userInfoEndpointConfiguration;

    /**
     * @param openIdConfiguration OpenID configuration
     * @param openIdProviderConfiguration Open ID Provider configuration
     * @param authorizationEndpointConfiguration Authorization endpoint configuration
     * @param endSessionEndpointConfiguration End-session endpoint configuration
     * @param introspectionEndpointConfiguration Introspection endpoint configuration
     * @param registrationEndpointConfiguration Registration endpoint configuration
     * @param revocationEndpointConfiguration Revocation endpoint configuration
     * @param tokenEndpointConfiguration Token endpoint configuration
     * @param userInfoEndpointConfiguration User Info endpoint configuration
     */
    public OpenIdFactory(@Nullable OpenIdConfiguration openIdConfiguration,
                         OpenIdProviderConfiguration openIdProviderConfiguration,
                         AuthorizationEndpointConfiguration authorizationEndpointConfiguration,
                         EndSessionEndpointConfiguration endSessionEndpointConfiguration,
                         IntrospectionEndpointConfiguration introspectionEndpointConfiguration,
                         RegistrationEndpointConfiguration registrationEndpointConfiguration,
                         RevocationEndpointConfiguration revocationEndpointConfiguration,
                         TokenEndpointConfiguration tokenEndpointConfiguration,
                         UserInfoEndpointConfiguration userInfoEndpointConfiguration
    ) {
        this.openIdConfiguration = openIdConfiguration;
        this.openIdProviderConfiguration = openIdProviderConfiguration;
        this.authorizationEndpointConfiguration = authorizationEndpointConfiguration;
        this.endSessionEndpointConfiguration = endSessionEndpointConfiguration;
        this.introspectionEndpointConfiguration = introspectionEndpointConfiguration;
        this.registrationEndpointConfiguration = registrationEndpointConfiguration;
        this.revocationEndpointConfiguration = revocationEndpointConfiguration;
        this.tokenEndpointConfiguration = tokenEndpointConfiguration;
        this.userInfoEndpointConfiguration = userInfoEndpointConfiguration;
    }

    /**
     *
     * @return a bean of type {@link OpenIdProviderMetadataSession}
     */
    @Bean
    @Singleton
    public OpenIdProviderMetadataSession openIdProviderMetadataSession() {
        return new OpenIdProviderMetadataSessionAdapter(openIdConfiguration, endSessionEndpointConfiguration);
    }

    /**
     *
     * @return a bean of type {@link OpenIdProviderMetadata}
     */
    @Bean
    @Singleton
    public OpenIdProviderMetadata openIdProviderMetadata() {
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
    @Bean
    @Singleton
    public OpenIdEndpoints openIdEndpoints(OpenIdProviderMetadata openIdProviderMetadata,
                                           OpenIdProviderMetadataSession openIdProviderMetadataSession) {
        return new OpenIdEndpointsAdapter(openIdProviderMetadata, openIdProviderMetadataSession);
    }


}
