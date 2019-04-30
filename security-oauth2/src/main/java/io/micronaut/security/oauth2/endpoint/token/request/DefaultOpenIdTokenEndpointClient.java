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

package io.micronaut.security.oauth2.endpoint.token.request;

import io.micronaut.context.BeanContext;
import io.micronaut.core.type.Argument;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.client.HttpClientConfiguration;
import io.micronaut.http.client.RxHttpClient;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.TokenEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.authorization.response.AuthorizationResponse;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.oauth2.endpoint.token.response.TokenErrorResponse;
import io.micronaut.security.oauth2.grants.AuthorizationCodeGrant;
import io.micronaut.security.oauth2.url.CallbackUrlBuilder;
import org.reactivestreams.Publisher;

import javax.inject.Singleton;

/**
 * Default implementation of {@link TokenEndpointClient}.
 *
 * @since 1.0.0
 * @author Sergio del Amo
 */
@Singleton
public class DefaultOpenIdTokenEndpointClient extends AbstractTokenEndpointClient<OpenIdTokenResponse> implements OpenIdTokenEndpointClient<OpenIdTokenResponse> {

    private final CallbackUrlBuilder callbackUrlBuilder;

    public DefaultOpenIdTokenEndpointClient(BeanContext beanContext,
                                            HttpClientConfiguration defaultClientConfiguration,
                                            CallbackUrlBuilder callbackUrlBuilder) {
        super(beanContext, defaultClientConfiguration);
        this.callbackUrlBuilder = callbackUrlBuilder;
    }

    protected Publisher<OpenIdTokenResponse> doSend(MutableHttpRequest<AuthorizationCodeGrant> request,
                                              OauthClientConfiguration clientConfiguration) {
        RxHttpClient client = getClient(clientConfiguration.getName());
        return client.retrieve(request, Argument.of(OpenIdTokenResponse.class), Argument.of(TokenErrorResponse.class));
    }

    @Override
    protected MediaType getMediaType(OauthClientConfiguration clientConfiguration) {
        return clientConfiguration.getOpenid()
                .flatMap(OpenIdClientConfiguration::getToken)
                .map(TokenEndpointConfiguration::getContentType)
                .orElse(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
    }

    /**
     * @return A Authorization Code Grant
     */
    @Override
    protected AuthorizationCodeGrant createBody(AuthorizationResponse authorizationResponse,
                                                OauthClientConfiguration clientConfiguration) {
        AuthorizationCodeGrant authorizationCodeGrant = super.createBody(authorizationResponse, clientConfiguration);
        authorizationCodeGrant.setRedirectUri(
                callbackUrlBuilder.build(authorizationResponse.getCallbackRequest(), clientConfiguration.getName()));
        return authorizationCodeGrant;
    }
}
