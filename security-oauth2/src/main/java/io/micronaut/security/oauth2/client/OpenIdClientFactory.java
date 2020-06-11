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
package io.micronaut.security.oauth2.client;

import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.BeanInstantiationException;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.async.SupplierUtil;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.oauth2.client.condition.OpenIdClientCondition;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.EndSessionEndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.EndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.authorization.request.AuthorizationRedirectHandler;
import io.micronaut.security.oauth2.endpoint.authorization.response.OpenIdAuthorizationResponseHandler;
import io.micronaut.security.oauth2.endpoint.endsession.request.EndSessionEndpoint;
import io.micronaut.security.oauth2.endpoint.endsession.request.EndSessionEndpointResolver;
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.umd.cs.findbugs.annotations.Nullable;
import javax.inject.Provider;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.function.Supplier;

/**
 * Factory to create beans related to the configuration of
 * OpenID clients.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Factory
@Internal
@Requires(configuration = "io.micronaut.security.token.jwt")
class OpenIdClientFactory {

    private static final Logger LOG = LoggerFactory.getLogger(OpenIdClientFactory.class);

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
     * @param oauthClientConfiguration The client configuration
     * @param openIdClientConfiguration The openid client configuration
     * @param issuerClient The client to request the metadata
     * @return The OpenID configuration
     */
    @EachBean(OpenIdClientConfiguration.class)
    DefaultOpenIdProviderMetadata openIdConfiguration(@Parameter OauthClientConfiguration oauthClientConfiguration,
                                                      @Parameter OpenIdClientConfiguration openIdClientConfiguration,
                                                      @Client HttpClient issuerClient) {
        DefaultOpenIdProviderMetadata providerMetadata = openIdClientConfiguration.getIssuer()
                .map(issuer -> {
                    try {
                        URL configurationUrl = new URL(issuer, StringUtils.prependUri(issuer.getPath(), openIdClientConfiguration.getConfigurationPath()));
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Sending request for OpenID configuration for provider [{}] to URL [{}]", openIdClientConfiguration.getName(), configurationUrl);
                        }
                        return issuerClient.toBlocking().retrieve(configurationUrl.toString(), DefaultOpenIdProviderMetadata.class);
                    } catch (HttpClientResponseException e) {
                        throw new BeanInstantiationException("Failed to retrieve OpenID configuration for " + openIdClientConfiguration.getName(), e);
                    } catch (MalformedURLException e) {
                        throw new BeanInstantiationException("Failure parsing issuer URL " + issuer.toString(), e);
                    }
                }).orElse(new DefaultOpenIdProviderMetadata());

        overrideFromConfig(providerMetadata, openIdClientConfiguration, oauthClientConfiguration);
        return providerMetadata;
    }

    /**
     * Creates an {@link OpenIdClient} from the provided parameters.
     *
     * @param openIdClientConfiguration The openid client configuration
     * @param clientConfiguration The client configuration
     * @param openIdProviderMetadata The open id provider metadata
     * @param openIdAuthenticationMapper The user details mapper
     * @param redirectUrlBuilder The redirect URL builder
     * @param authorizationResponseHandler The authorization response handler
     * @param endSessionEndpointResolver The end session resolver
     * @param endSessionCallbackUrlBuilder The end session callback URL builder
     * @return The OpenID client, or null if the client configuration does not allow it
     */
    @EachBean(OpenIdClientConfiguration.class)
    @Requires(condition = OpenIdClientCondition.class)
    DefaultOpenIdClient openIdClient(@Parameter OpenIdClientConfiguration openIdClientConfiguration,
                                     @Parameter OauthClientConfiguration clientConfiguration,
                                     @Parameter Provider<DefaultOpenIdProviderMetadata> openIdProviderMetadata,
                                     @Parameter @Nullable OpenIdAuthenticationMapper openIdAuthenticationMapper,
                                     AuthorizationRedirectHandler redirectUrlBuilder,
                                     OpenIdAuthorizationResponseHandler authorizationResponseHandler,
                                     EndSessionEndpointResolver endSessionEndpointResolver,
                                     EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder) {
        Supplier<OpenIdProviderMetadata> metadataSupplier = SupplierUtil.memoized(openIdProviderMetadata::get);
        EndSessionEndpoint endSessionEndpoint = null;
        if (openIdClientConfiguration.getEndSession().isEnabled()) {
            endSessionEndpoint = endSessionEndpointResolver.resolve(clientConfiguration, metadataSupplier, endSessionCallbackUrlBuilder).orElse(null);
        }

        return new DefaultOpenIdClient(clientConfiguration,
                metadataSupplier,
                openIdAuthenticationMapper,
                redirectUrlBuilder,
                authorizationResponseHandler,
                beanContext,
                endSessionEndpoint);
    }

    private void overrideFromConfig(DefaultOpenIdProviderMetadata configuration,
                                    OpenIdClientConfiguration openIdClientConfiguration,
                                    OauthClientConfiguration oauthClientConfiguration) {
        openIdClientConfiguration.getJwksUri().ifPresent(configuration::setJwksUri);

        oauthClientConfiguration.getIntrospection().ifPresent(introspection -> {
            introspection.getUrl().ifPresent(configuration::setIntrospectionEndpoint);
            introspection.getAuthMethod().ifPresent(authMethod -> configuration.setIntrospectionEndpointAuthMethodsSupported(Collections.singletonList(authMethod.toString())));
        });
        oauthClientConfiguration.getRevocation().ifPresent(revocation -> {
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
