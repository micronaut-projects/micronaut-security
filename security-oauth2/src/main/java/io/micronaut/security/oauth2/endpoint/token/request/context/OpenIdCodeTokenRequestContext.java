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
package io.micronaut.security.oauth2.endpoint.token.request.context;

import io.micronaut.core.type.Argument;
import io.micronaut.http.MediaType;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.TokenEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.authorization.response.AuthorizationResponse;
import io.micronaut.security.oauth2.endpoint.token.response.DefaultOpenIdTokenResponse;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.oauth2.endpoint.token.response.TokenErrorResponse;
import io.micronaut.security.oauth2.grants.AuthorizationCodeGrant;
import io.micronaut.security.oauth2.url.CallbackUrlBuilder;

import java.util.Map;

public class OpenIdCodeTokenRequestContext extends AbstractTokenRequestContext<Map<String, String>, DefaultOpenIdTokenResponse> {

    private final AuthorizationResponse authorizationResponse;
    private final CallbackUrlBuilder callbackUrlBuilder;

    public OpenIdCodeTokenRequestContext(AuthorizationResponse authorizationResponse,
                                         CallbackUrlBuilder callbackUrlBuilder,
                                         SecureEndpoint endpoint,
                                         OauthClientConfiguration clientConfiguration) {
        super(getMediaType(clientConfiguration), endpoint, clientConfiguration);
        this.authorizationResponse = authorizationResponse;
        this.callbackUrlBuilder = callbackUrlBuilder;
    }

    protected static MediaType getMediaType(OauthClientConfiguration clientConfiguration) {
        return clientConfiguration.getOpenid()
                .flatMap(OpenIdClientConfiguration::getToken)
                .map(TokenEndpointConfiguration::getContentType)
                .orElse(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
    }

    @Override
    public Map<String, String> getGrant() {
        AuthorizationCodeGrant codeGrant = new AuthorizationCodeGrant();
        codeGrant.setCode(authorizationResponse.getCode());
        codeGrant.setRedirectUri(callbackUrlBuilder
                .build(authorizationResponse.getCallbackRequest(), clientConfiguration.getName()));
        return codeGrant.toMap();
    }

    @Override
    public Argument<DefaultOpenIdTokenResponse> getResponseType() {
        return Argument.of(DefaultOpenIdTokenResponse.class);
    }

    @Override
    public Argument<?> getErrorResponseType() {
        return Argument.of(TokenErrorResponse.class);
    }
}
