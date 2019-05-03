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
package io.micronaut.security.oauth2.endpoint.token.request.password;

import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.security.authentication.AuthenticationProvider;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.response.OauthUserDetailsMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdUserDetailsMapper;
import io.micronaut.security.oauth2.endpoint.token.response.validation.OpenIdTokenResponseValidator;
import io.micronaut.security.oauth2.grants.GrantType;
import io.micronaut.security.oauth2.openid.OpenIdProviderMetadata;

import javax.annotation.Nullable;

@Factory
public class PasswordGrantFactory {

    @EachBean(OauthClientConfiguration.class)
    AuthenticationProvider passwordGrantProvider(
            @Parameter OauthClientConfiguration clientConfiguration,
            @Parameter @Nullable OauthUserDetailsMapper userDetailsMapper,
            @Parameter @Nullable OpenIdUserDetailsMapper openIdUserDetailsMapper,
            @Parameter @Nullable OpenIdProviderMetadata openIdProviderMetadata,
            TokenEndpointClient tokenEndpointClient,
            @Nullable OpenIdTokenResponseValidator tokenResponseValidator) {

        if (clientConfiguration.isEnabled()) {
            if (clientConfiguration.getGrantType() == GrantType.PASSWORD) {
                if (clientConfiguration.getToken().isPresent()) {
                    if (userDetailsMapper != null) {
                        return new OauthPasswordAuthenticationProvider(tokenEndpointClient, clientConfiguration, userDetailsMapper);
                    }
                } else if (clientConfiguration.getOpenid().isPresent()) {
                    if (openIdUserDetailsMapper != null && openIdProviderMetadata != null && tokenResponseValidator != null) {
                        return new OpenIdPasswordAuthenticationProvider(clientConfiguration, openIdProviderMetadata, tokenEndpointClient, openIdUserDetailsMapper, tokenResponseValidator);
                    }
                }
            }
        }

        return null;
    }
}
