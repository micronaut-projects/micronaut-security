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
package io.micronaut.security.oauth2;

import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.security.oauth2.client.DefaultOauthClient;
import io.micronaut.security.oauth2.client.OauthClient;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.EndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.authorization.request.AuthorizationRedirectUrlBuilder;
import io.micronaut.security.oauth2.endpoint.authorization.response.OauthAuthorizationResponseHandler;
import io.micronaut.security.oauth2.endpoint.token.response.OauthUserDetailsMapper;
import io.micronaut.security.oauth2.grants.GrantType;

@Factory
public class OauthFactory {

    @EachBean(OauthUserDetailsMapper.class)
    OauthClient oauthClient(@Parameter OauthUserDetailsMapper userDetailsMapper,
                            @Parameter OauthClientConfiguration clientConfiguration,
                            AuthorizationRedirectUrlBuilder redirectUrlBuilder,
                            OauthAuthorizationResponseHandler authorizationResponseHandler,
                            BeanContext beanContext) {
        if (clientConfiguration.isEnabled()) {
            if (clientConfiguration.getAuthorization().flatMap(EndpointConfiguration::getUrl).isPresent()) {
                if (clientConfiguration.getToken().flatMap(EndpointConfiguration::getUrl).isPresent()) {
                    if (clientConfiguration.getGrantType() == GrantType.AUTHORIZATION_CODE) {
                        return new DefaultOauthClient(clientConfiguration, userDetailsMapper, redirectUrlBuilder, authorizationResponseHandler, beanContext);
                    }
                }
            }
        }
        return null;
    }
}
