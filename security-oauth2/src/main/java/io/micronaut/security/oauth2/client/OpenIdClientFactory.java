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
import io.micronaut.context.BeanProvider;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.BeanInstantiationException;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.StringUtils;
import io.micronaut.core.util.SupplierUtil;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.json.JsonMapper;
import io.micronaut.security.oauth2.client.condition.OpenIdClientCondition;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.EndSessionEndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.EndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.SecureEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.authorization.request.AuthorizationRedirectHandler;
import io.micronaut.security.oauth2.endpoint.authorization.response.OpenIdAuthorizationResponseHandler;
import io.micronaut.security.oauth2.endpoint.endsession.request.EndSessionEndpoint;
import io.micronaut.security.oauth2.endpoint.endsession.request.EndSessionEndpointResolver;
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
                        throw new BeanInstantiationException("Failure parsing issuer URL " + issuer, e);
                    }
                }).orElse(null);

        return overrideFromConfig(providerMetadata, openIdClientConfiguration, oauthClientConfiguration);
    }

    /**
     * Creates an {@link OpenIdClient} from the provided parameters.
     *
     * @param openIdClientConfiguration The openid client configuration
     * @param clientConfiguration The client configuration
     * @param openIdProviderMetadata The open id provider metadata
     * @param authenticationMapper The user details mapper
     * @param redirectUrlBuilder The redirect URL builder
     * @param authorizationResponseHandler The authorization response handler
     * @param endSessionEndpointResolver The end session resolver
     * @param endSessionCallbackUrlBuilder The end session callback URL builder
     * @return The OpenID client, or null if the client configuration does not allow it
     */
    @EachBean(OpenIdClientConfiguration.class)
    @Requires(condition = OpenIdClientCondition.class)
    @SuppressWarnings("java:S107")
    DefaultOpenIdClient openIdClient(@Parameter OpenIdClientConfiguration openIdClientConfiguration,
                                     @Parameter OauthClientConfiguration clientConfiguration,
                                     @Parameter BeanProvider<DefaultOpenIdProviderMetadata> openIdProviderMetadata,
                                     @Parameter @Nullable OpenIdAuthenticationMapper authenticationMapper,
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
                authenticationMapper,
                redirectUrlBuilder,
                authorizationResponseHandler,
                beanContext,
                endSessionEndpoint);
    }

    @NonNull
    private static DefaultOpenIdProviderMetadata overrideFromConfig(@Nullable DefaultOpenIdProviderMetadata providerMetadata,
                                                             @NonNull OpenIdClientConfiguration openIdClientConfiguration,
                                                             @NonNull OauthClientConfiguration oauthClientConfiguration) {
        EndSessionEndpointConfiguration endSession = openIdClientConfiguration.getEndSession();
        return new DefaultOpenIdProviderMetadata(providerMetadata == null ? null : providerMetadata.getAuthorizationEndpoint(),
            providerMetadata == null ? null : providerMetadata.getIdTokenSigningAlgValuesSupported(),
            providerMetadata == null ? null : providerMetadata.getIssuer(),
            openIdClientConfiguration.getJwksUri().orElseGet(() -> providerMetadata == null ? null : providerMetadata.getJwksUri()),
            providerMetadata == null ? null : providerMetadata.getAcrValuesSupported(),
            providerMetadata == null ? null : providerMetadata.getResponseTypesSupported(),
            providerMetadata == null ? null : providerMetadata.getResponseModesSupported(),
            providerMetadata == null ? null : providerMetadata.getScopesSupported(),
            providerMetadata == null ? null : providerMetadata.getGrantTypesSupported(),
            providerMetadata == null ? null : providerMetadata.getSubjectTypesSupported(),
            openIdClientConfiguration.getToken().flatMap(SecureEndpointConfiguration::getUrl).orElseGet(() -> providerMetadata == null ? null : providerMetadata.getTokenEndpoint()),
            oauthClientConfiguration.getToken().flatMap(SecureEndpointConfiguration::getAuthMethod).map(authMethod -> Collections.singletonList(authMethod.toString())).orElseGet(() -> providerMetadata == null ? null : providerMetadata.getTokenEndpointAuthMethodsSupported()),
            openIdClientConfiguration.getUserInfo().flatMap(EndpointConfiguration::getUrl).orElseGet(() -> providerMetadata == null ? null : providerMetadata.getUserinfoEndpoint()),
            openIdClientConfiguration.getRegistration().flatMap(EndpointConfiguration::getUrl).orElseGet(() -> providerMetadata == null ? null : providerMetadata.getRegistrationEndpoint()),
            providerMetadata == null ? null : providerMetadata.getClaimsSupported(),
            providerMetadata == null ? null : providerMetadata.getCodeChallengeMethodsSupported(),
            oauthClientConfiguration.getIntrospection().flatMap(SecureEndpointConfiguration::getUrl).orElseGet(() -> providerMetadata == null ? null : providerMetadata.getIntrospectionEndpoint()),
            oauthClientConfiguration.getIntrospection().flatMap(SecureEndpointConfiguration::getAuthMethod).map(authMethod -> Collections.singletonList(authMethod.toString())).orElseGet(() -> providerMetadata == null ? null : providerMetadata.getIntrospectionEndpointAuthMethodsSupported()),
            oauthClientConfiguration.getRevocation().flatMap(SecureEndpointConfiguration::getUrl).orElseGet(() -> providerMetadata == null ? null : providerMetadata.getRevocationEndpoint()),
            oauthClientConfiguration.getRevocation().flatMap(SecureEndpointConfiguration::getAuthMethod).map(authMethod -> Collections.singletonList(authMethod.toString())).orElseGet(() -> providerMetadata == null ? null : providerMetadata.getRevocationEndpointAuthMethodsSupported()),
            endSession.isEnabled() ? endSession.getUrl().orElseGet(() -> providerMetadata == null ? null : providerMetadata.getEndSessionEndpoint()) : providerMetadata == null ? null : providerMetadata.getEndSessionEndpoint(),
            providerMetadata == null ? null : providerMetadata.getRequestParameterSupported(),
            providerMetadata == null ? null : providerMetadata.getRequestUriParameterSupported(),
            providerMetadata == null ? null : providerMetadata.getRequireRequestUriRegistration(),
            providerMetadata == null ? null : providerMetadata.getRequestObjectSigningAlgValuesSupported(),
            providerMetadata == null ? null : providerMetadata.getServiceDocumentation(),
            providerMetadata == null ? null : providerMetadata.getIdTokenEncryptionEncValuesSupported(),
            providerMetadata == null ? null : providerMetadata.getDisplayValuesSupported(),
            providerMetadata == null ? null : providerMetadata.getClaimTypesSupported(),
            providerMetadata == null ? null : providerMetadata.getOpTosUri(),
            providerMetadata == null ? null : providerMetadata.getOpPolicyUri(),
            providerMetadata == null ? null : providerMetadata.getUriLocalesSupported(),
            providerMetadata == null ? null : providerMetadata.getClaimsLocalesSupported(),
            providerMetadata == null ? null : providerMetadata.getUserInfoEncryptionAlgValuesSupported(),
            providerMetadata == null ? null : providerMetadata.getUserinfoEncryptionEncValuesSupported(),
            providerMetadata == null ? null : providerMetadata.getTokenEndpointAuthSigningAlgValuesSupported(),
            providerMetadata == null ? null : providerMetadata.getRequestObjectEncryptionAlgValuesSupported(),
            providerMetadata == null ? null : providerMetadata.getRequestObjectEncryptionEncValuesSupported(),
            providerMetadata == null ? null : providerMetadata.getCheckSessionIframe());
    }
}
