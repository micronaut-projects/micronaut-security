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
import io.micronaut.context.annotation.Requires;
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
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.url.OauthRouteUrlBuilder;
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
 * Default implementation of {@link OpenIdAuthorizationResponseHandler}.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Singleton
@Requires(configuration = "io.micronaut.security.token.jwt")
public class DefaultOpenIdAuthorizationResponseHandler implements OpenIdAuthorizationResponseHandler {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultOpenIdAuthorizationResponseHandler.class);

    private final OpenIdTokenResponseValidator tokenResponseValidator;
    private final OpenIdUserDetailsMapper defaultUserDetailsMapper;
    private final TokenEndpointClient tokenEndpointClient;
    private final OauthRouteUrlBuilder oauthRouteUrlBuilder;
    private final @Nullable StateValidator stateValidator;

    /**
     * @param tokenResponseValidator The token response validator
     * @param userDetailsMapper The user details mapper
     * @param tokenEndpointClient The token endpoint client
     * @param oauthRouteUrlBuilder The oauth route url builder
     * @param stateValidator The state validator
     */
    public DefaultOpenIdAuthorizationResponseHandler(OpenIdTokenResponseValidator tokenResponseValidator,
                                                     DefaultOpenIdUserDetailsMapper userDetailsMapper,
                                                     TokenEndpointClient tokenEndpointClient,
                                                     OauthRouteUrlBuilder oauthRouteUrlBuilder,
                                                     @Nullable StateValidator stateValidator) {
        this.tokenResponseValidator = tokenResponseValidator;
        this.defaultUserDetailsMapper = userDetailsMapper;
        this.tokenEndpointClient = tokenEndpointClient;
        this.oauthRouteUrlBuilder = oauthRouteUrlBuilder;
        this.stateValidator = stateValidator;
    }

    @Override
    public Publisher<AuthenticationResponse> handle(
            OpenIdAuthorizationResponse authorizationResponse,
            OauthClientConfiguration clientConfiguration,
            OpenIdProviderMetadata openIdProviderMetadata,
            @Nullable OpenIdUserDetailsMapper userDetailsMapper,
            SecureEndpoint tokenEndpoint) {

        if (stateValidator != null) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Validating state found in the authorization response from provider [{}]", clientConfiguration.getName());
            }
            State state = authorizationResponse.getState();
            stateValidator.validate(authorizationResponse.getCallbackRequest(), state);
        } else {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Skipping state validation, no state validator found");
            }
        }

        String nonce = authorizationResponse.getNonce();

        OpenIdCodeTokenRequestContext requestContext = new OpenIdCodeTokenRequestContext(authorizationResponse, oauthRouteUrlBuilder, tokenEndpoint, clientConfiguration);

        return Flowable.fromPublisher(
                tokenEndpointClient.sendRequest(requestContext))
                .switchMap(response -> {
                    if (LOG.isTraceEnabled()) {
                        LOG.trace("Token endpoint returned a success response. Validating the JWT");
                    }
                    return Flowable.create(emitter -> {
                        Optional<JWT> jwt = tokenResponseValidator.validate(clientConfiguration, openIdProviderMetadata, response, nonce);
                        if (jwt.isPresent()) {
                            try {
                                if (LOG.isTraceEnabled()) {
                                    LOG.trace("Token validation succeeded. Creating a user details");
                                }
                                OpenIdClaims claims = new JWTOpenIdClaims(jwt.get().getJWTClaimsSet());
                                OpenIdUserDetailsMapper openIdUserDetailsMapper = userDetailsMapper != null ? userDetailsMapper : defaultUserDetailsMapper;
                                emitter.onNext(openIdUserDetailsMapper.createUserDetails(clientConfiguration.getName(), response, claims));
                                emitter.onComplete();
                            } catch (ParseException e) {
                                //Should never happen as validation succeeded
                                emitter.onError(e);
                            }
                        } else {
                            if (LOG.isTraceEnabled()) {
                                LOG.trace("Token validation failed. Failing authentication");
                            }
                            //TODO: Create a more meaningful response
                            emitter.onNext(new AuthenticationFailed());
                            emitter.onComplete();
                        }
                    }, BackpressureStrategy.ERROR);
                });
    }

}
