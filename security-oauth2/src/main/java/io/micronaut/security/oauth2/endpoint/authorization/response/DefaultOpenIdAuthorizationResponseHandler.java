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

import com.nimbusds.jwt.JWT;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.context.annotation.Requires;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.authorization.state.InvalidStateException;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.authorization.state.validation.StateValidator;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.request.context.OpenIdCodeTokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.DefaultOpenIdAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.JWTOpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.validation.OpenIdTokenResponseValidator;
import io.micronaut.security.oauth2.url.OauthRouteUrlBuilder;
import reactor.core.publisher.FluxSink;
import reactor.core.publisher.Flux;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.inject.Singleton;
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
    private final OpenIdAuthenticationMapper defaultAuthenticationMapper;
    private final TokenEndpointClient tokenEndpointClient;
    private final OauthRouteUrlBuilder oauthRouteUrlBuilder;
    private final @Nullable StateValidator stateValidator;

    /**
     * @param tokenResponseValidator The token response validator
     * @param authenticationMapper Authentication Mapper
     * @param tokenEndpointClient The token endpoint client
     * @param oauthRouteUrlBuilder The oauth route url builder
     * @param stateValidator The state validator
     */
    public DefaultOpenIdAuthorizationResponseHandler(OpenIdTokenResponseValidator tokenResponseValidator,
                                                     DefaultOpenIdAuthenticationMapper authenticationMapper,
                                                     TokenEndpointClient tokenEndpointClient,
                                                     OauthRouteUrlBuilder oauthRouteUrlBuilder,
                                                     @Nullable StateValidator stateValidator) {
        this.tokenResponseValidator = tokenResponseValidator;
        this.defaultAuthenticationMapper = authenticationMapper;
        this.tokenEndpointClient = tokenEndpointClient;
        this.oauthRouteUrlBuilder = oauthRouteUrlBuilder;
        this.stateValidator = stateValidator;
    }

    @Override
    public Publisher<AuthenticationResponse> handle(
            OpenIdAuthorizationResponse authorizationResponse,
            OauthClientConfiguration clientConfiguration,
            OpenIdProviderMetadata openIdProviderMetadata,
            @Nullable OpenIdAuthenticationMapper authenticationMapper,
            SecureEndpoint tokenEndpoint) {
        try {
            validateState(authorizationResponse, clientConfiguration);
        } catch (InvalidStateException e) {
            return Flux.just(new AuthenticationFailed("State validation failed: " + e.getMessage()));
        }
        return Flux.from(sendRequest(authorizationResponse, clientConfiguration, tokenEndpoint))
                .switchMap(response -> createAuthenticationResponse(authorizationResponse.getNonce(),
                        clientConfiguration,
                        openIdProviderMetadata,
                        response,
                        authenticationMapper,
                        authorizationResponse.getState()));
    }
    
    /**
     * Validates the Authorization response state.
     * @param authorizationResponse The authorization response
     * @param clientConfiguration The client configuration
     * @throws InvalidStateException if the state did not pass validation
     */
    private void validateState(OpenIdAuthorizationResponse authorizationResponse, OauthClientConfiguration clientConfiguration) throws InvalidStateException {
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
    }

    /**
     *
     * @param authorizationResponse The authorization response
     * @param clientConfiguration The client configuration
     * @param tokenEndpoint The token endpoint
     * @return The open id token response from the Authorization server
     */
    private Publisher<OpenIdTokenResponse> sendRequest(OpenIdAuthorizationResponse authorizationResponse,
                                               OauthClientConfiguration clientConfiguration,
                                               SecureEndpoint tokenEndpoint) {
        OpenIdCodeTokenRequestContext requestContext = new OpenIdCodeTokenRequestContext(authorizationResponse, oauthRouteUrlBuilder, tokenEndpoint, clientConfiguration);
        return tokenEndpointClient.sendRequest(requestContext);
    }

    /**
     *
     * @param nonce Nonce
     * @param clientConfiguration The client configuration
     * @param openIdProviderMetadata The provider metadata
     * @param openIdTokenResponse OpenID token response
     * @param authenticationMapper The user details mapper
     * @param state State
     * @return An authentication response publisher
     */
    private Flux<AuthenticationResponse> createAuthenticationResponse(String nonce,
                                                                            OauthClientConfiguration clientConfiguration,
                                                                            OpenIdProviderMetadata openIdProviderMetadata,
                                                                            OpenIdTokenResponse openIdTokenResponse,
                                                                            @Nullable OpenIdAuthenticationMapper authenticationMapper,
                                                                            @Nullable State state) {
        return Flux.create(emitter -> {
            try {
                Optional<AuthenticationResponse> authenticationResponse = validateOpenIdTokenResponse(nonce,
                        clientConfiguration,
                        openIdProviderMetadata,
                        openIdTokenResponse,
                        authenticationMapper,
                        state);
                if (authenticationResponse.isPresent()) {
                    emitter.next(authenticationResponse.get());
                    emitter.complete();
                } else {
                    if (LOG.isTraceEnabled()) {
                        LOG.trace("Token validation failed. Failing authentication");
                    }
                    emitter.error(AuthenticationResponse.exception("JWT validation failed"));
                }
            } catch (ParseException e) {
                //Should never happen as validation succeeded
                emitter.error(e);
            }
        }, FluxSink.OverflowStrategy.ERROR);
    }

    /**
     *
     * @param nonce Nonce
     * @param clientConfiguration The client configuration
     * @param openIdProviderMetadata The provider metadata
     * @param openIdTokenResponse OpenID token response
     * @param authenticationMapper The user details mapper
     * @param state State
     * @return An Authentication response if the open id token could  be validated
     * @throws ParseException If the payload of the JWT doesn't represent a valid JSON object and a JWT claims set.
     */
    private Optional<AuthenticationResponse> validateOpenIdTokenResponse(String nonce,
                                                                           OauthClientConfiguration clientConfiguration,
                                                                           OpenIdProviderMetadata openIdProviderMetadata,
                                                                           OpenIdTokenResponse openIdTokenResponse,
                                                                           @Nullable OpenIdAuthenticationMapper authenticationMapper,
                                                                           @Nullable State state) throws ParseException {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Token endpoint returned a success response. Validating the JWT");
        }
        Optional<JWT> jwt = tokenResponseValidator.validate(clientConfiguration, openIdProviderMetadata, openIdTokenResponse, nonce);
        if (jwt.isPresent()) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Token validation succeeded. Creating a user details");
            }
            OpenIdClaims claims = new JWTOpenIdClaims(jwt.get().getJWTClaimsSet());
            OpenIdAuthenticationMapper openIdAuthenticationMapper = authenticationMapper != null ? authenticationMapper : defaultAuthenticationMapper;
            return Optional.of(openIdAuthenticationMapper.createAuthenticationResponse(clientConfiguration.getName(), openIdTokenResponse, claims, state));
        }
        return Optional.empty();
    }
}
