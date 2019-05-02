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

package io.micronaut.security.oauth2.openid;

import com.nimbusds.jose.jwk.KeyType;
import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.exceptions.BeanInstantiationException;
import io.micronaut.http.client.HttpClientConfiguration;
import io.micronaut.http.client.RxHttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.oauth2.client.DefaultOpenIdClient;
import io.micronaut.security.oauth2.client.OpenIdClient;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.*;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.endpoint.authorization.request.AuthorizationRedirectUrlBuilder;
import io.micronaut.security.oauth2.endpoint.authorization.response.OpenIdAuthorizationResponseHandler;
import io.micronaut.security.oauth2.grants.GrantType;
import io.micronaut.security.oauth2.endpoint.authorization.request.ResponseType;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Collections;
import java.util.Optional;

/**
 * Factory which creates beans of type Creates a HTTP Declarative client to communicate with an OpenID connect Discovery endpoint.
 * The discovery endpoint is declared by the property micronaut.security.oauth2.openid.issuer
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Factory
public class OpenIdFactory {

    private final BeanContext beanContext;

    OpenIdFactory(BeanContext beanContext) {
        this.beanContext = beanContext;
    }

    @EachBean(OpenIdClientConfiguration.class)
    OpenIdConfiguration openIdConfiguration(@Parameter OpenIdClientConfiguration clientConfiguration,
                                            HttpClientConfiguration defaultHttpConfiguration) {
        OpenIdConfiguration openIdConfiguration = clientConfiguration.getIssuer()
                .map(issuer -> {
                    RxHttpClient issuerClient = beanContext.createBean(RxHttpClient.class, issuer, defaultHttpConfiguration);
                    try {
                        return issuerClient.toBlocking().retrieve(clientConfiguration.getConfigurationPath(), OpenIdConfiguration.class);
                    } catch (HttpClientResponseException e) {
                        throw new BeanInstantiationException("Failed to retrieve OpenID configuration for " + clientConfiguration.getName(), e);
                    }
                }).orElse(new OpenIdConfiguration());

        overrideFromConfig(openIdConfiguration, clientConfiguration);
        return openIdConfiguration;
    }

    @EachBean(OpenIdConfiguration.class)
    DefaultOpenIdClient openIdClient(@Parameter OauthClientConfiguration oauthClientConfiguration,
                              @Parameter OpenIdProviderMetadata openIdProviderMetadata,
                              AuthorizationRedirectUrlBuilder redirectUrlBuilder,
                              OpenIdAuthorizationResponseHandler authorizationResponseHandler,
                              BeanContext beanContext) {
        if (oauthClientConfiguration.isEnabled()) {
            Optional<OpenIdClientConfiguration> openIdClientConfiguration = oauthClientConfiguration.getOpenid();
            if (openIdClientConfiguration.map(OpenIdClientConfiguration::getIssuer).isPresent()) {
                if (oauthClientConfiguration.getGrantType() == GrantType.AUTHORIZATION_CODE) {
                    Optional<AuthorizationEndpointConfiguration> authorization = openIdClientConfiguration.get().getAuthorization();
                    if (!authorization.isPresent() || authorization.get().getResponseType() == ResponseType.CODE) {
                        return new DefaultOpenIdClient(oauthClientConfiguration, openIdProviderMetadata, redirectUrlBuilder, authorizationResponseHandler, beanContext);
                    }
                }
            }
        }
        return null;
    }

    @EachBean(OpenIdConfiguration.class)
    JwksSignatureConfiguration signatureConfiguration(OpenIdProviderMetadata openIdProviderMetadata) {
        return new JwksSignatureConfiguration() {
            @Nonnull
            @Override
            public String getUrl() {
                return openIdProviderMetadata.getJwksUri();
            }

            @Nullable
            @Override
            public KeyType getKeyType() {
                return null;
            }
        };
    }

    private void overrideFromConfig(OpenIdConfiguration configuration,
                                    OpenIdClientConfiguration openIdClientConfiguration) {
        openIdClientConfiguration.getJwksUri().ifPresent(configuration::setJwksUri);

        openIdClientConfiguration.getIntrospection().ifPresent(introspection -> {
            introspection.getUrl().ifPresent(configuration::setIntrospectionEndpoint);
            introspection.getAuthMethod().ifPresent(authMethod -> configuration.setIntrospectionEndpointAuthMethodsSupported(Collections.singletonList(authMethod.toString())));
        });
        openIdClientConfiguration.getRevocation().ifPresent(revocation -> {
            revocation.getUrl().ifPresent(configuration::setRevocationEndpoint);
            revocation.getAuthMethod().ifPresent(authMethod -> configuration.setRevocationEndpointAuthMethodsSupported(Collections.singletonList(authMethod.toString())));
        });
        openIdClientConfiguration.getRegistration()
                .flatMap(EndpointConfiguration::getUrl).ifPresent(configuration::setRegistrationEndpoint);
        openIdClientConfiguration.getUserInfo()
                .flatMap(EndpointConfiguration::getUrl).ifPresent(configuration::setUserinfoEndpoint);
        openIdClientConfiguration.getAuthorization()
                .flatMap(EndpointConfiguration::getUrl).ifPresent(configuration::setAuthorizationEndpoint);
        openIdClientConfiguration.getToken().ifPresent(token -> {
            token.getUrl().ifPresent(configuration::setTokenEndpoint);
            token.getAuthMethod().ifPresent(authMethod -> configuration.setTokenEndpointAuthMethodsSupported(Collections.singletonList(authMethod.toString())));
        });

    }

}
