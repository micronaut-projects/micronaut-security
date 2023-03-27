/*
 * Copyright 2017-2023 original authors
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
import io.micronaut.context.annotation.Context;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parallel;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.SupplierUtil;
import io.micronaut.security.oauth2.client.condition.OpenIdClientCondition;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.AuthorizationEndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.EndSessionEndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.EndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.OauthAuthorizationEndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.SecureEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.authorization.request.AuthorizationRedirectHandler;
import io.micronaut.security.oauth2.endpoint.authorization.response.OpenIdAuthorizationResponseHandler;
import io.micronaut.security.oauth2.endpoint.endsession.request.EndSessionEndpoint;
import io.micronaut.security.oauth2.endpoint.endsession.request.EndSessionEndpointResolver;
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper;

import java.util.Collections;
import java.util.Optional;
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
     * @param openIdProviderMetadataFetcher OpenID Provider metadata Fetcher
     * @return The OpenID configuration
     */
    @Parallel
    @Context
    @EachBean(OpenIdClientConfiguration.class)
    DefaultOpenIdProviderMetadata openIdConfiguration(@Parameter OauthClientConfiguration oauthClientConfiguration,
                                                      @Parameter OpenIdClientConfiguration openIdClientConfiguration,
                                                      @Parameter OpenIdProviderMetadataFetcher openIdProviderMetadataFetcher) {
        DefaultOpenIdProviderMetadata providerMetadata = openIdProviderMetadataFetcher.fetch();
        overrideFromConfig(providerMetadata, openIdClientConfiguration, oauthClientConfiguration);
        return providerMetadata;
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
        String endSessionEndpoint = providerMetadata == null ? null : providerMetadata.getEndSessionEndpoint();
        EndSessionEndpointConfiguration endSession = openIdClientConfiguration.getEndSession();
        Optional<AuthorizationEndpointConfiguration> authorization = openIdClientConfiguration.getAuthorization();
        return new DefaultOpenIdProviderMetadata(authorization.flatMap(OauthAuthorizationEndpointConfiguration::getUrl).orElseGet(() -> providerMetadata == null ? null : providerMetadata.getAuthorizationEndpoint()),
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
            authorization.flatMap(OauthAuthorizationEndpointConfiguration::getCodeChallengeMethod).map(Collections::singletonList).orElseGet(() -> providerMetadata == null ? null : providerMetadata.getCodeChallengeMethodsSupported()),
            oauthClientConfiguration.getIntrospection().flatMap(SecureEndpointConfiguration::getUrl).orElseGet(() -> providerMetadata == null ? null : providerMetadata.getIntrospectionEndpoint()),
            oauthClientConfiguration.getIntrospection().flatMap(SecureEndpointConfiguration::getAuthMethod).map(authMethod -> Collections.singletonList(authMethod.toString())).orElseGet(() -> providerMetadata == null ? null : providerMetadata.getIntrospectionEndpointAuthMethodsSupported()),
            oauthClientConfiguration.getRevocation().flatMap(SecureEndpointConfiguration::getUrl).orElseGet(() -> providerMetadata == null ? null : providerMetadata.getRevocationEndpoint()),
            oauthClientConfiguration.getRevocation().flatMap(SecureEndpointConfiguration::getAuthMethod).map(authMethod -> Collections.singletonList(authMethod.toString())).orElseGet(() -> providerMetadata == null ? null : providerMetadata.getRevocationEndpointAuthMethodsSupported()),
            endSession.isEnabled() ? endSession.getUrl().orElse(endSessionEndpoint) : endSessionEndpoint,
            providerMetadata == null ? null : providerMetadata.getRequestParameterSupported(),
            providerMetadata == null ? null : providerMetadata.getRequestUriParameterSupported(),
            providerMetadata == null ? null : providerMetadata.getRequireRequestUriRegistration(),
            providerMetadata == null ? null : providerMetadata.getRequestObjectSigningAlgValuesSupported(),
            providerMetadata == null ? null : providerMetadata.getServiceDocumentation(),
            providerMetadata == null ? null : providerMetadata.getIdTokenEncryptionEncValuesSupported(),
            providerMetadata == null ? null : providerMetadata.getDisplayValuesSupported(),
            providerMetadata == null ? null : providerMetadata.getClaimTypesSupported(),
            providerMetadata == null ? null : providerMetadata.getClaimsParameterSupported(),
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
