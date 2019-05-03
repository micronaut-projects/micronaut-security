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

import com.nimbusds.jwt.JWT;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.request.context.OpenIdCodeTokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.*;
import io.micronaut.security.oauth2.endpoint.token.response.validation.OpenIdTokenResponseValidator;
import io.micronaut.security.oauth2.endpoint.authorization.state.validation.StateValidator;
import io.micronaut.security.oauth2.openid.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.url.CallbackUrlBuilder;
import io.reactivex.BackpressureStrategy;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.inject.Singleton;
import java.text.ParseException;
import java.util.Optional;

/**
 * Default implementation of {@link OauthAuthorizationResponseHandler}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Singleton
public class DefaultOpenIdAuthorizationResponseHandler implements OpenIdAuthorizationResponseHandler {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultOpenIdAuthorizationResponseHandler.class);

    private final OpenIdTokenResponseValidator tokenResponseValidator;
    private final OpenIdUserDetailsMapper userDetailsMapper;
    private final TokenEndpointClient tokenEndpointClient;
    private final CallbackUrlBuilder callbackUrlBuilder;
    private final @Nullable StateValidator stateValidator;


    DefaultOpenIdAuthorizationResponseHandler(OpenIdTokenResponseValidator tokenResponseValidator,
                                                     OpenIdUserDetailsMapper userDetailsMapper,
                                                     TokenEndpointClient tokenEndpointClient,
                                                     CallbackUrlBuilder callbackUrlBuilder,
                                                     @Nullable StateValidator stateValidator) {
        this.tokenResponseValidator = tokenResponseValidator;
        this.userDetailsMapper = userDetailsMapper;
        this.tokenEndpointClient = tokenEndpointClient;
        this.callbackUrlBuilder = callbackUrlBuilder;
        this.stateValidator = stateValidator;
    }

    @Override
    public Publisher<AuthenticationResponse> handle(
            AuthorizationResponse authorizationResponse,
            OauthClientConfiguration clientConfiguration,
            OpenIdProviderMetadata openIdProviderMetadata,
            SecureEndpoint tokenEndpoint) {

        if (stateValidator != null) {
            State state = authorizationResponse.getState();
            stateValidator.validate(authorizationResponse.getCallbackRequest(), state);
        }

        OpenIdCodeTokenRequestContext requestContext = new OpenIdCodeTokenRequestContext(authorizationResponse, callbackUrlBuilder, tokenEndpoint, clientConfiguration);

        return Flowable.fromPublisher(
                tokenEndpointClient.sendRequest(requestContext))
                .switchMap(response -> {
                    return Flowable.create(emitter -> {
                        Optional<JWT> jwt = tokenResponseValidator.validate(clientConfiguration, openIdProviderMetadata, response);
                        if (jwt.isPresent()) {
                            try {
                                OpenIdClaims claims = new JWTOpenIdClaims(jwt.get().getJWTClaimsSet());
                                emitter.onNext(userDetailsMapper.createUserDetails(clientConfiguration.getName(), response, claims));
                                emitter.onComplete();
                            } catch (ParseException e) {
                                //Should never happen as validation succeeded
                                emitter.onError(e);
                            }
                        } else {
                            //TODO: Create a more meaningful response
                            emitter.onNext(new AuthenticationFailed());
                            emitter.onComplete();
                        }
                    }, BackpressureStrategy.ERROR);
                });
    }

}
