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

package io.micronaut.security.oauth2.client;

import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.exceptions.BeanInstantiationException;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.client.HttpClientConfiguration;
import io.micronaut.http.client.LoadBalancer;
import io.micronaut.http.client.RxHttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.AuthorizationEndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.EndSessionEndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.EndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.authorization.request.AuthorizationRedirectUrlBuilder;
import io.micronaut.security.oauth2.endpoint.authorization.request.ResponseType;
import io.micronaut.security.oauth2.endpoint.authorization.response.OpenIdAuthorizationResponseHandler;
import io.micronaut.security.oauth2.endpoint.endsession.request.EndSessionEndpoint;
import io.micronaut.security.oauth2.endpoint.endsession.request.EndSessionEndpointResolver;
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdUserDetailsMapper;
import io.micronaut.security.oauth2.grants.GrantType;

import javax.annotation.Nullable;
import java.util.Collections;
import java.util.Optional;

/**
 * Factory to create beans related to the configuration of
 * OpenID clients.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Factory
@Internal
class OpenIdClientFactory {

    private final BeanContext beanContext;

    /**
     * @param beanContext The bean context
     */
    OpenIdClientFactory(BeanContext beanContext) {
        this.beanContext = beanContext;
    }

    /**
     * Retrieves OpenID configuration from the provided issuer.
     *
     * @param clientConfiguration The client configuration
     * @param defaultHttpConfiguration The default HTTP client configuration
     * @return The OpenID configuration
     */
    @EachBean(OpenIdClientConfiguration.class)
    OpenIdConfiguration openIdConfiguration(@Parameter OpenIdClientConfiguration clientConfiguration,
                                                   HttpClientConfiguration defaultHttpConfiguration) {
        OpenIdConfiguration openIdConfiguration = clientConfiguration.getIssuer()
                .map(issuer -> {
                    RxHttpClient issuerClient = beanContext.createBean(RxHttpClient.class, LoadBalancer.empty(), defaultHttpConfiguration);
                    String configurationUrl = StringUtils.prependUri(issuer.toString(), clientConfiguration.getConfigurationPath());
                    try {
                        return issuerClient.toBlocking().retrieve(configurationUrl, OpenIdConfiguration.class);
                    } catch (HttpClientResponseException e) {
                        throw new BeanInstantiationException("Failed to retrieve OpenID configuration for " + clientConfiguration.getName(), e);
                    }
                }).orElse(new OpenIdConfiguration());

        overrideFromConfig(openIdConfiguration, clientConfiguration);
        return openIdConfiguration;
    }

    /**
     * Creates an {@link OpenIdClient} from the provided parameters.
     *
     * @param oauthClientConfiguration The client configuration
     * @param openIdProviderMetadata The OpenID provider metadata
     * @param userDetailsMapper The user details mapper
     * @param redirectUrlBuilder The redirect URL builder
     * @param authorizationResponseHandler The authorization response handler
     * @param endSessionEndpointResolver The end session resolver
     * @param endSessionCallbackUrlBuilder The end session callback URL builder
     * @return The OpenID client, or null if the client configuration does not allow it
     */
    @EachBean(OpenIdConfiguration.class)
    DefaultOpenIdClient openIdClient(@Parameter OauthClientConfiguration oauthClientConfiguration,
                                            @Parameter OpenIdProviderMetadata openIdProviderMetadata,
                                            @Parameter @Nullable OpenIdUserDetailsMapper userDetailsMapper,
                                            AuthorizationRedirectUrlBuilder redirectUrlBuilder,
                                            OpenIdAuthorizationResponseHandler authorizationResponseHandler,
                                            EndSessionEndpointResolver endSessionEndpointResolver,
                                            EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder) {
        if (oauthClientConfiguration.isEnabled()) {
            Optional<OpenIdClientConfiguration> openIdClientConfiguration = oauthClientConfiguration.getOpenid();
            if (openIdClientConfiguration.map(OpenIdClientConfiguration::getIssuer).isPresent()) {
                if (oauthClientConfiguration.getGrantType() == GrantType.AUTHORIZATION_CODE) {
                    OpenIdClientConfiguration clientConfiguration = openIdClientConfiguration.get();
                    Optional<AuthorizationEndpointConfiguration> authorization = clientConfiguration.getAuthorization();
                    if (!authorization.isPresent() || authorization.get().getResponseType() == ResponseType.CODE) {

                        EndSessionEndpoint endSessionEndpoint = null;
                        if (clientConfiguration.getEndSession().isEnabled()) {
                            endSessionEndpoint = endSessionEndpointResolver.resolve(oauthClientConfiguration, openIdProviderMetadata, endSessionCallbackUrlBuilder).orElse(null);
                        }

                        return new DefaultOpenIdClient(oauthClientConfiguration,
                                openIdProviderMetadata,
                                userDetailsMapper,
                                redirectUrlBuilder,
                                authorizationResponseHandler,
                                beanContext,
                                endSessionEndpoint);
                    }
                }
            }
        }
        return null;
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

        EndSessionEndpointConfiguration endSession = openIdClientConfiguration.getEndSession();
        if (endSession.isEnabled()) {
            endSession.getUrl().ifPresent(configuration::setEndSessionEndpoint);
        }

    }

}
