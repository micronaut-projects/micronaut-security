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
package io.micronaut.security.oauth2.endpoint.authorization.response;

import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.authorization.state.InvalidStateException;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.authorization.state.validation.StateValidator;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.request.context.OauthCodeTokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.OauthUserDetailsMapper;
import reactor.core.publisher.Flux;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.micronaut.core.annotation.Nullable;
import jakarta.inject.Singleton;

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

    @Nullable
    private final StateValidator stateValidator;

    /**
     * @param tokenEndpointClient The token endpoint client
     * @param stateValidator The state validator
     */
    DefaultOauthAuthorizationResponseHandler(TokenEndpointClient tokenEndpointClient,
                                             @Nullable StateValidator stateValidator) {
        this.tokenEndpointClient = tokenEndpointClient;
        this.stateValidator = stateValidator;
    }

    @Override
    public Publisher<AuthenticationResponse> handle(
            AuthorizationResponse authorizationResponse,
            OauthClientConfiguration clientConfiguration,
            OauthUserDetailsMapper userDetailsMapper,
            SecureEndpoint tokenEndpoint) {

        State state;
        if (stateValidator != null) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Validating state found in the authorization response from provider [{}]", clientConfiguration.getName());
            }
            state = authorizationResponse.getState();
            try {
                stateValidator.validate(authorizationResponse.getCallbackRequest(), state);
            } catch (InvalidStateException e) {
                return Flux.just(new AuthenticationFailed("State validation failed: " + e.getMessage()));
            }

        } else {
            state = null;
            if (LOG.isTraceEnabled()) {
                LOG.trace("Skipping state validation, no state validator found");
            }
        }

        OauthCodeTokenRequestContext context = new OauthCodeTokenRequestContext(authorizationResponse, tokenEndpoint, clientConfiguration);

        return Flux.from(
                tokenEndpointClient.sendRequest(context))
                .switchMap(response -> {
                    if (LOG.isTraceEnabled()) {
                        LOG.trace("Token endpoint returned a success response. Creating a user details");
                    }
                    return Flux.from(userDetailsMapper.createAuthenticationResponse(response, state))
                            .map(AuthenticationResponse.class::cast);
                });
    }
}
