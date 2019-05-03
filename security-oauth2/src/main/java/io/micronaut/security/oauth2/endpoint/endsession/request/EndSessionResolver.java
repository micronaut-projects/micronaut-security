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
import io.micronaut.security.oauth2.openid.OpenIdProviderMetadata;

import javax.inject.Singleton;
import java.net.URL;
import java.util.Optional;

@Singleton
public class EndSessionResolver {

    public static final String OKTA = "okta";
    public static final String COGNITO = "cognito";
    public static final String AUTH0 = "auth0";

    private final BeanContext beanContext;

    EndSessionResolver(BeanContext beanContext) {
        this.beanContext = beanContext;
    }

    public Optional<EndSessionRequest> resolve(OauthClientConfiguration oauthClientConfiguration,
                                               OpenIdProviderMetadata openIdProviderMetadata,
                                               EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder) {

        String providerName = oauthClientConfiguration.getName();
        EndSessionRequest endSessionRequest = beanContext.findBean(EndSessionRequest.class, Qualifiers.byName(providerName)).orElse(null);

        if (endSessionRequest == null) {
            String issuer = oauthClientConfiguration.getOpenid().flatMap(OpenIdClientConfiguration::getIssuer).map(URL::toString).orElse(null);

            if (issuer != null) {
                if (issuer.contains(OKTA)) {
                    endSessionRequest = new OktaEndSessionRequest(endSessionCallbackUrlBuilder, oauthClientConfiguration, openIdProviderMetadata);
                } else if (issuer.contains(COGNITO)) {
                    endSessionRequest = new AwsCognitoEndSessionRequest(endSessionCallbackUrlBuilder, oauthClientConfiguration, openIdProviderMetadata);
                } else if (issuer.contains(AUTH0)) {
                    endSessionRequest = new Auth0EndSessionRequest(endSessionCallbackUrlBuilder, oauthClientConfiguration, openIdProviderMetadata);
                }
            }
        }

        return Optional.ofNullable(endSessionRequest);
    }
}
