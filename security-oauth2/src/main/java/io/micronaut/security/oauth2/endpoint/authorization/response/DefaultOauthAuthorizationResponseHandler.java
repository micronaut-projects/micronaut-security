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
package io.micronaut.security.oauth2.endpoint.authorization.response;

import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.token.request.DefaultTokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.request.context.OauthCodeTokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.OauthUserDetailsMapper;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;

/**
 * Default implementation of {@link OauthAuthorizationResponseHandler}.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Singleton
public class DefaultOauthAuthorizationResponseHandler implements OauthAuthorizationResponseHandler {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultOauthAuthorizationResponseHandler.class);

    private final TokenEndpointClient tokenEndpointClient;

    /**
     * @param tokenEndpointClient The token endpoint client
     */
    DefaultOauthAuthorizationResponseHandler(TokenEndpointClient tokenEndpointClient) {
        this.tokenEndpointClient = tokenEndpointClient;
    }

    @Override
    public Publisher<AuthenticationResponse> handle(
            AuthorizationResponse authorizationResponse,
            OauthClientConfiguration clientConfiguration,
            OauthUserDetailsMapper userDetailsMapper,
            SecureEndpoint tokenEndpoint) {

        OauthCodeTokenRequestContext context = new OauthCodeTokenRequestContext(authorizationResponse, tokenEndpoint, clientConfiguration);

        return Flowable.fromPublisher(
                tokenEndpointClient.sendRequest(context))
                .switchMap(response -> {
                    if (LOG.isTraceEnabled()) {
                        LOG.trace("Token endpoint returned a success response. Creating a user details");
                    }
                    return Flowable.fromPublisher(userDetailsMapper.createUserDetails(response))
                            .map(AuthenticationResponse.class::cast);
                });
    }
}
