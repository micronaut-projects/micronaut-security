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
package io.micronaut.security.oauth2.endpoint.endsession.request;

import io.micronaut.context.BeanContext;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;
import java.net.URL;
import java.util.Optional;

import static io.micronaut.security.oauth2.endpoint.endsession.request.AuthorizationServer.OKTA;
import static io.micronaut.security.oauth2.endpoint.endsession.request.AuthorizationServer.AUTH0;
import static io.micronaut.security.oauth2.endpoint.endsession.request.AuthorizationServer.COGNITO;

/**
 * Responsible for resolving which end session request to use
 * for a given OpenID client configuration.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Singleton
public class EndSessionEndpointResolver {

    private static final Logger LOG = LoggerFactory.getLogger(EndSessionEndpointResolver.class);

    private final BeanContext beanContext;
    private final AuthorizationServerResolver authorizationServerResolver;

    /**
     * @param beanContext The bean context
     * @param authorizationServerResolver Authorization Server resolver
     */
    public EndSessionEndpointResolver(BeanContext beanContext,
                                      AuthorizationServerResolver authorizationServerResolver) {
        this.beanContext = beanContext;
        this.authorizationServerResolver = authorizationServerResolver;
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

        String authorizationServer = authorizationServerResolver.resolve(issuer);
        if (authorizationServer == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No EndSessionEndpoint can be resolved. Authorization server resolved is null for issuer [{}]", issuer);
            }
            return Optional.empty();
        }

        if (authorizationServer.equals(OKTA.getName())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Resolved the OktaEndSessionEndpoint for provider [{}]", providerName);
            }
            return Optional.of(new OktaEndSessionEndpoint(endSessionCallbackUrlBuilder, oauthClientConfiguration, openIdProviderMetadata));
        } else if (authorizationServer.equals(COGNITO.getName())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Resolved the AwsCognitoEndSessionEndpoint for provider [{}]", providerName);
            }
            return Optional.of(new AwsCognitoEndSessionEndpoint(endSessionCallbackUrlBuilder, oauthClientConfiguration, openIdProviderMetadata));
        } else if (authorizationServer.equals(AUTH0.getName())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Resolved the Auth0EndSessionEndpoint for provider [{}]", providerName);
            }
            Optional.of(new Auth0EndSessionEndpoint(endSessionCallbackUrlBuilder, oauthClientConfiguration, openIdProviderMetadata));
        }

        return Optional.empty();
    }
}
