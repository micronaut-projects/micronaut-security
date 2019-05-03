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

import javax.inject.Singleton;
import java.net.URL;
import java.util.Optional;

/**
 * Responsible for resolving which end session request to use
 * for a given OpenID client configuration.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Singleton
public class EndSessionEndpointResolver {

    private static final String OKTA = "okta";
    private static final String COGNITO = "cognito";
    private static final String AUTH0 = "auth0";

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

        String providerName = oauthClientConfiguration.getName();
        EndSessionEndpoint endSessionEndpoint = beanContext.findBean(EndSessionEndpoint.class, Qualifiers.byName(providerName)).orElse(null);

        if (endSessionEndpoint == null) {
            String issuer = oauthClientConfiguration.getOpenid().flatMap(OpenIdClientConfiguration::getIssuer).map(URL::toString).orElse(null);

            if (issuer != null) {
                if (issuer.contains(OKTA)) {
                    endSessionEndpoint = new OktaEndSessionEndpoint(endSessionCallbackUrlBuilder, oauthClientConfiguration, openIdProviderMetadata);
                } else if (issuer.contains(COGNITO)) {
                    endSessionEndpoint = new AwsCognitoEndSessionEndpoint(endSessionCallbackUrlBuilder, oauthClientConfiguration, openIdProviderMetadata);
                } else if (issuer.contains(AUTH0)) {
                    endSessionEndpoint = new Auth0EndSessionRequest(endSessionCallbackUrlBuilder, oauthClientConfiguration, openIdProviderMetadata);
                }
            }
        }

        return Optional.ofNullable(endSessionEndpoint);
    }
}
