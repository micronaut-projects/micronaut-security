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
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.StringUtils;
import io.micronaut.core.util.SupplierUtil;
import io.micronaut.http.client.HttpClientRegistry;
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

import java.net.URL;
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
@Requires(beans = HttpClientRegistry.class)
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

    private void overrideFromConfig(DefaultOpenIdProviderMetadata configuration,
                                    OpenIdClientConfiguration openIdClientConfiguration,
                                    OauthClientConfiguration oauthClientConfiguration) {
        overrideIssuer(configuration, openIdClientConfiguration);

        openIdClientConfiguration.getJwksUri().ifPresent(configuration::setJwksUri);

        oauthClientConfiguration.getIntrospection().ifPresent(introspection -> {
            introspection.getUrl().ifPresent(configuration::setIntrospectionEndpoint);
            introspection.getAuthenticationMethod().ifPresent(authMethod -> configuration.setIntrospectionEndpointAuthMethodsSupported(Collections.singletonList(authMethod)));
        });
        oauthClientConfiguration.getRevocation().ifPresent(revocation -> {
            revocation.getUrl().ifPresent(configuration::setRevocationEndpoint);
            revocation.getAuthenticationMethod().ifPresent(authMethod -> configuration.setRevocationEndpointAuthMethodsSupported(Collections.singletonList(authMethod)));
        });
        openIdClientConfiguration.getRegistration()
            .flatMap(EndpointConfiguration::getUrl).ifPresent(configuration::setRegistrationEndpoint);
        openIdClientConfiguration.getUserInfo()
            .flatMap(EndpointConfiguration::getUrl).ifPresent(configuration::setUserinfoEndpoint);
        openIdClientConfiguration.getAuthorization().ifPresent(authorizationEndpointConfiguration -> {
            authorizationEndpointConfiguration.getUrl().ifPresent(configuration::setAuthorizationEndpoint);
            authorizationEndpointConfiguration.getCodeChallengeMethod()
                .ifPresent(codeChallengeMethod -> configuration.setCodeChallengeMethodsSupported(Collections.singletonList(codeChallengeMethod)));
        });
        openIdClientConfiguration.getToken().ifPresent(token -> {
            token.getUrl().ifPresent(configuration::setTokenEndpoint);
            token.getAuthenticationMethod().ifPresent(authMethod -> configuration.setTokenEndpointAuthMethodsSupported(Collections.singletonList(authMethod)));
        });

        EndSessionEndpointConfiguration endSession = openIdClientConfiguration.getEndSession();
        if (endSession.isEnabled()) {
            endSession.getUrl().ifPresent(configuration::setEndSessionEndpoint);
        }
    }

    /**
     * Validates the issuer of the provider metadata against the configured issuer identifier.
     * <p>
     * OpenID Connect Discovery 1.0, section 4.3: the {@code issuer} value returned MUST be identical to the Issuer URL
     * that was used to retrieve the configuration. The issuer is asserted by the provider, so an issuer that does not
     * match the configured one is discarded and the configured one is used instead. That way a provider cannot get
     * tokens of another issuer accepted by announcing that issuer in its discovery document. The comparison only
     * tolerates the case of the scheme and a trailing slash (see {@link OpenIdIssuers#equivalent(String, String)}).
     *
     * @param configuration The provider metadata
     * @param openIdClientConfiguration The openid client configuration
     */
    private static void overrideIssuer(DefaultOpenIdProviderMetadata configuration,
                                       OpenIdClientConfiguration openIdClientConfiguration) {
        Optional<String> expected = openIdClientConfiguration.getIssuerIdentifier();
        if (expected.isEmpty()) {
            return;
        }
        String expectedIssuer = expected.get();
        String discoveredIssuer = configuration.getIssuer();
        if (StringUtils.isEmpty(discoveredIssuer)) {
            configuration.setIssuer(expectedIssuer);
            return;
        }
        if (OpenIdIssuers.equivalent(expectedIssuer, discoveredIssuer)) {
            return;
        }
        configuration.setIssuer(expectedIssuer);
        boolean explicitIdentifier = openIdClientConfiguration.getIssuer()
            .map(URL::toString)
            .map(url -> !url.equals(expectedIssuer))
            .orElse(true);
        if (explicitIdentifier) {
            if (LOG.isInfoEnabled()) {
                LOG.info("The issuer [{}] of the OpenID provider metadata of client [{}] differs from the configured issuer identifier [{}]. The configured issuer identifier is used.", discoveredIssuer, openIdClientConfiguration.getName(), expectedIssuer);
            }
        } else if (LOG.isErrorEnabled()) {
            LOG.error("The issuer [{}] of the OpenID provider metadata of client [{}] does not match the configured issuer [{}]. OpenID Connect Discovery 1.0 section 4.3 requires both to be identical. The announced issuer is ignored and ID tokens are only accepted if their iss claim is [{}]. If the provider issues tokens with a different iss (for example, discovery is fetched over an internal URL), set micronaut.security.oauth2.clients.{}.openid.issuer-identifier to the expected iss value.", discoveredIssuer, openIdClientConfiguration.getName(), expectedIssuer, expectedIssuer, openIdClientConfiguration.getName());
        }
    }
}
