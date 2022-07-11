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
package io.micronaut.security.oauth2.endpoint.endsession.request;

import io.micronaut.context.BeanContext;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.config.SecurityConfiguration;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder;
import io.micronaut.security.token.reader.TokenResolver;
import jakarta.inject.Singleton;
import java.net.URL;
import java.util.Optional;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Responsible for resolving which end session request to use for a given OpenID client configuration.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Singleton
public class EndSessionEndpointResolver {

    private static final Logger LOG = LoggerFactory.getLogger(EndSessionEndpointResolver.class);

    private final BeanContext beanContext;

    /**
     * @param beanContext The bean context
     */
    public EndSessionEndpointResolver(BeanContext beanContext) {
        this.beanContext = beanContext;
    }

    /**
     * Attempts to resolve an end session request in the
     * following order:
     *
     * 1. A bean lookup with the a name qualifier of the provider name
     * 2. Comparing the issuer URL to a supported list of providers
     *
     * @param oauthClientConfiguration The client configuration
     * @param openIdProviderMetadata The provider metadata
     * @param endSessionCallbackUrlBuilder The end session callback builder
     * @return An optional end session request
     */
    public Optional<EndSessionEndpoint> resolve(OauthClientConfiguration oauthClientConfiguration,
                                                OpenIdProviderMetadata openIdProviderMetadata,
                                                EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder) {

        return resolve(oauthClientConfiguration, () -> openIdProviderMetadata, endSessionCallbackUrlBuilder);
    }

    /**
     * Attempts to resolve an end session request in the
     * following order:
     *
     * 1. A bean lookup with the a name qualifier of the provider name
     * 2. Comparing the issuer URL to a supported list of providers
     *
     * @param oauthClientConfiguration The client configuration
     * @param openIdProviderMetadata The provider metadata supplier
     * @param endSessionCallbackUrlBuilder The end session callback builder
     * @return An optional end session request
     */
    public Optional<EndSessionEndpoint> resolve(OauthClientConfiguration oauthClientConfiguration,
                                                Supplier<OpenIdProviderMetadata> openIdProviderMetadata,
                                                EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder) {

        String providerName = oauthClientConfiguration.getName();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Resolving the end session endpoint for provider [{}]. Looking for a bean with the provider name qualifier", providerName);
        }

        EndSessionEndpoint endSessionEndpoint = beanContext.findBean(EndSessionEndpoint.class, Qualifiers.byName(providerName)).orElse(null);

        if (endSessionEndpoint != null) {
            return Optional.of(endSessionEndpoint);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("No EndSessionEndpoint bean found with a name qualifier of [{}]", providerName);
        }

        String issuer = oauthClientConfiguration.getOpenid().flatMap(OpenIdClientConfiguration::getIssuer).map(URL::toString).orElse(null);

        if (issuer == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No EndSessionEndpoint can be resolved. Issuer is null for provider [{}]", providerName);
            }
            return Optional.empty();
        }

        return getEndSessionEndpoint(oauthClientConfiguration, openIdProviderMetadata, endSessionCallbackUrlBuilder, providerName, issuer);
    }

    @NonNull
    private Optional<EndSessionEndpoint> getEndSessionEndpoint(OauthClientConfiguration oauthClientConfiguration,
                                                               Supplier<OpenIdProviderMetadata> openIdProviderMetadata,
                                                               EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder,
                                                               @NonNull String providerName,
                                                               @NonNull String issuer) {
        Optional<AuthorizationServer> inferOptional = AuthorizationServer.infer(issuer);
        if (!inferOptional.isPresent()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No EndSessionEndpoint can be resolved. The issuer for provider [{}] does not match any of the providers supported by default", providerName);
            }
            return Optional.empty();
        }
        switch (inferOptional.get()) {
            case OKTA:
            case KEYCLOAK_17:
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Resolved the OpenIdEndSessionEndpoint for provider [{}]", providerName);
                }
                return openIdEndSessionEndpoint(oauthClientConfiguration, openIdProviderMetadata, endSessionCallbackUrlBuilder);
            case COGNITO:
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Resolved the AwsCognitoEndSessionEndpoint for provider [{}]", providerName);
                }
                return Optional.of(new AwsCognitoEndSessionEndpoint(endSessionCallbackUrlBuilder, oauthClientConfiguration, openIdProviderMetadata));
            case AUTH0:
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Resolved the Auth0EndSessionEndpoint for provider [{}]", providerName);
                }
                return Optional.of(new Auth0EndSessionEndpoint(endSessionCallbackUrlBuilder, oauthClientConfiguration, openIdProviderMetadata));
            case KEYCLOAK:
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Resolved the KeycloakEndSessionEndpoint for provider [{}]", providerName);
                }
                return Optional.of(new KeycloakEndSessionEndpoint(endSessionCallbackUrlBuilder, oauthClientConfiguration, openIdProviderMetadata));
            default:
                return Optional.empty();
        }
    }

    @NonNull
    private Optional<EndSessionEndpoint> openIdEndSessionEndpoint(OauthClientConfiguration oauthClientConfiguration,
                                                                Supplier<OpenIdProviderMetadata> openIdProviderMetadata,
                                                                EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder) {
        SecurityConfiguration securityConfiguration = beanContext.getBean(SecurityConfiguration.class);
        TokenResolver tokenResolver = beanContext.getBean(TokenResolver.class);
        return Optional.of(new OpenIdEndSessionEndpoint(endSessionCallbackUrlBuilder,
                oauthClientConfiguration,
                openIdProviderMetadata,
                securityConfiguration,
                tokenResolver));
    }
}
