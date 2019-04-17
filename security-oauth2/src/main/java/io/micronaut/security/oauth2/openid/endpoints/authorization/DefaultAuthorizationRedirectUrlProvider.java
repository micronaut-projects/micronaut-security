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

package io.micronaut.security.oauth2.openid.endpoints.authorization;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.oauth2.openid.configuration.OpenIdProviderMetadata;

import javax.inject.Singleton;

/**
 * Default implementation of {@link io.micronaut.security.oauth2.openid.endpoints.authorization.AuthorizationRedirectUrlProvider}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Singleton
@Requires(beans = {AuthenticationRequestProvider.class, OpenIdProviderMetadata.class})
public class DefaultAuthorizationRedirectUrlProvider implements AuthorizationRedirectUrlProvider {

    private final AuthenticationRequestProvider authenticationRequestProvider;
    private final OpenIdProviderMetadata openIdProviderMetadata;
    private final AuthorizationRedirectUrlBuilder authorizationRedirectUrlBuilder;

    /**
     *
     * @param authenticationRequestProvider Authentication Request provider
     * @param openIdProviderMetadata OpenID provider metadata.
     * @param authorizationRedirectUrlBuilder Authorization Redirect url builder
     */
    public DefaultAuthorizationRedirectUrlProvider(AuthenticationRequestProvider authenticationRequestProvider,
                                                   OpenIdProviderMetadata openIdProviderMetadata,
                                                   AuthorizationRedirectUrlBuilder authorizationRedirectUrlBuilder) {
        this.authenticationRequestProvider = authenticationRequestProvider;
        this.openIdProviderMetadata = openIdProviderMetadata;
        this.authorizationRedirectUrlBuilder = authorizationRedirectUrlBuilder;
    }

    /**
     * @param request the Original request prior redirect.
     * @return A URL to redirect the user to the OpenID Provider authorization endpoint.
     */
    @Override
    public String resolveAuthorizationRedirectUrl(HttpRequest<?> request) {
        AuthenticationRequest authenticationRequest = authenticationRequestProvider.generateAuthenticationRequest(request);
        return authorizationRedirectUrlBuilder.resolveAuthorizationRedirectUrl(authenticationRequest, openIdProviderMetadata.getAuthorizationEndpoint());
    }

}
