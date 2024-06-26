/*
 * Copyright 2017-2023 original authors
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
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence.PkcePersistence;
import io.micronaut.security.oauth2.endpoint.authorization.state.InvalidStateException;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.authorization.state.validation.StateValidator;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.request.context.OpenIdCodeTokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.JWTOpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.oauth2.endpoint.token.response.validation.OpenIdTokenResponseValidator;
import io.micronaut.security.oauth2.endpoint.token.response.validation.ReactiveOpenIdTokenResponseValidator;
import io.micronaut.security.oauth2.url.OauthRouteUrlBuilder;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import java.text.ParseException;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Default implementation of {@link OpenIdAuthorizationResponseHandler}.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 * @param <T> Request
 */
@Requires(classes = JWT.class)
@Requires(beans = { ReactiveOpenIdTokenResponseValidator.class, OpenIdAuthenticationMapper.class, TokenEndpointClient.class, OauthRouteUrlBuilder.class})
@Singleton
@Requires(configuration = "io.micronaut.security.token.jwt")
public class DefaultOpenIdAuthorizationResponseHandler<T> implements OpenIdAuthorizationResponseHandler {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultOpenIdAuthorizationResponseHandler.class);

    private final ReactiveOpenIdTokenResponseValidator<JWT> tokenResponseValidator;
    private final OpenIdAuthenticationMapper defaultAuthenticationMapper;
    private final TokenEndpointClient tokenEndpointClient;
    private final OauthRouteUrlBuilder<T> oauthRouteUrlBuilder;
    private final @Nullable StateValidator stateValidator;
    private final @Nullable PkcePersistence pkcePersistence;

    /**
     * @param tokenResponseValidator The token response validator
     * @param authenticationMapper   Authentication Mapper
     * @param tokenEndpointClient    The token endpoint client
     * @param oauthRouteUrlBuilder   The oauth route url builder
     * @param stateValidator         The state validator
     * @param pkcePersistence        The PKCE persistence
     */
    @Inject
    public DefaultOpenIdAuthorizationResponseHandler(ReactiveOpenIdTokenResponseValidator<JWT> tokenResponseValidator,
                                                     OpenIdAuthenticationMapper authenticationMapper,
                                                     TokenEndpointClient tokenEndpointClient,
                                                     OauthRouteUrlBuilder<T> oauthRouteUrlBuilder,
                                                     @Nullable StateValidator stateValidator,
                                                     @Nullable PkcePersistence pkcePersistence) {
        this.tokenResponseValidator = tokenResponseValidator;
        this.defaultAuthenticationMapper = authenticationMapper;
        this.tokenEndpointClient = tokenEndpointClient;
        this.oauthRouteUrlBuilder = oauthRouteUrlBuilder;
        this.stateValidator = stateValidator;
        this.pkcePersistence = pkcePersistence;
    }

    /**
     * @param tokenResponseValidator The token response validator
     * @param authenticationMapper   Authentication Mapper
     * @param tokenEndpointClient    The token endpoint client
     * @param oauthRouteUrlBuilder   The oauth route url builder
     * @param stateValidator         The state validator
     * @param pkcePersistence        The PKCE persistence
     * @param blockingExecutor       An executor for blocking operations
     * @deprecated Use {@link DefaultOpenIdAuthorizationResponseHandler(ReactiveOpenIdTokenResponseValidator, OpenIdAuthenticationMapper, TokenEndpointClient, OauthRouteUrlBuilder, StateValidator, PkcePersistence)} instead.
     */
    @Deprecated(since = "4.8.0", forRemoval = true)
    public DefaultOpenIdAuthorizationResponseHandler(OpenIdTokenResponseValidator tokenResponseValidator,
                                                     OpenIdAuthenticationMapper authenticationMapper,
                                                     TokenEndpointClient tokenEndpointClient,
                                                     OauthRouteUrlBuilder<T> oauthRouteUrlBuilder,
                                                     @Nullable StateValidator stateValidator,
                                                     @Nullable PkcePersistence pkcePersistence,
                                                     @Named(TaskExecutors.BLOCKING) ExecutorService blockingExecutor) {
        this.tokenResponseValidator = (clientConfiguration1, openIdProviderMetadata1, openIdTokenResponse, nonce) -> {
            Optional<JWT> jwtOptional = tokenResponseValidator.validate(clientConfiguration1, openIdProviderMetadata1, openIdTokenResponse, nonce);
            return jwtOptional.map(Mono::just).orElseGet(Mono::empty);
        };
        this.defaultAuthenticationMapper = authenticationMapper;
        this.tokenEndpointClient = tokenEndpointClient;
        this.oauthRouteUrlBuilder = oauthRouteUrlBuilder;
        this.stateValidator = stateValidator;
        this.pkcePersistence = pkcePersistence;
    }

    /**
     * @param tokenResponseValidator The token response validator
     * @param authenticationMapper   Authentication Mapper
     * @param tokenEndpointClient    The token endpoint client
     * @param oauthRouteUrlBuilder   The oauth route url builder
     * @param stateValidator         The state validator
     * @param pkcePersistence        The PKCE persistence
     * @deprecated Use {@link #DefaultOpenIdAuthorizationResponseHandler(ReactiveOpenIdTokenResponseValidator, OpenIdAuthenticationMapper, TokenEndpointClient, OauthRouteUrlBuilder, StateValidator, PkcePersistence)} instead
     */
    @Deprecated(forRemoval = true, since = "2.7.0")
    public DefaultOpenIdAuthorizationResponseHandler(OpenIdTokenResponseValidator tokenResponseValidator,
                                                     OpenIdAuthenticationMapper authenticationMapper,
                                                     TokenEndpointClient tokenEndpointClient,
                                                     OauthRouteUrlBuilder<T> oauthRouteUrlBuilder,
                                                     @Nullable StateValidator stateValidator,
                                                     @Nullable PkcePersistence pkcePersistence) {
        this(tokenResponseValidator, authenticationMapper, tokenEndpointClient, oauthRouteUrlBuilder, stateValidator, pkcePersistence, Executors.newCachedThreadPool());
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
                .switchMap(response -> Flux.from(createAuthenticationResponse(authorizationResponse.getNonce(),
                    clientConfiguration,
                    openIdProviderMetadata,
                    response,
                    authenticationMapper,
                    authorizationResponse.getState())).map(AuthenticationResponse.class::cast));
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
        OpenIdCodeTokenRequestContext requestContext = new OpenIdCodeTokenRequestContext(authorizationResponse,
            oauthRouteUrlBuilder,
            tokenEndpoint,
            clientConfiguration,
            pkcePersistence == null ? null :
                pkcePersistence.retrieveCodeVerifier(authorizationResponse.getCallbackRequest()).orElse(null));
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
     * @return An Authentication response if the open id token could  be validated
     * @throws ParseException If the payload of the JWT doesn't represent a valid JSON object and a JWT claims set.
     */
    private Mono<AuthenticationResponse> createAuthenticationResponse(String nonce,
                                                                      OauthClientConfiguration clientConfiguration,
                                                                      OpenIdProviderMetadata openIdProviderMetadata,
                                                                      OpenIdTokenResponse openIdTokenResponse,
                                                                      @Nullable OpenIdAuthenticationMapper authenticationMapper,
                                                                      @Nullable State state) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Token endpoint returned a success response. Validating the JWT");
        }
        return Mono.from(tokenResponseValidator.validate(clientConfiguration, openIdProviderMetadata, openIdTokenResponse, nonce))
                .flatMap(jwt -> {
                    if (LOG.isTraceEnabled()) {
                        LOG.trace("Token validation succeeded. Creating a user details");
                    }
                    try {
                        OpenIdClaims claims = new JWTOpenIdClaims(jwt.getJWTClaimsSet());
                        OpenIdAuthenticationMapper openIdAuthenticationMapper = authenticationMapper != null ? authenticationMapper : defaultAuthenticationMapper;
                        return Mono.from(openIdAuthenticationMapper.createAuthenticationResponse(clientConfiguration.getName(), openIdTokenResponse, claims, state));
                    } catch (ParseException e) {
                        return Mono.error(e);
                    }
                });
    }

}
