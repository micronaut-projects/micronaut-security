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

package io.micronaut.security.oauth2.handlers;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.client.RxHttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.oauth2.openid.endpoints.authorization.InvalidStateException;
import io.micronaut.security.oauth2.openid.endpoints.authorization.StateValidator;
import io.micronaut.security.oauth2.openid.endpoints.token.AuthorizationCodeGrantRequestGenerator;
import io.micronaut.security.oauth2.openid.idtoken.IdTokenAccessTokenResponse;
import io.micronaut.security.oauth2.responses.AuthenticationResponse;
import io.reactivex.Flowable;
import io.reactivex.Single;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.inject.Named;
import javax.inject.Singleton;
import java.util.Optional;

/**
 * Default implementation of {@link AuthorizationResponseHandler}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
//@Requires(beans = {AuthorizationCodeGrantRequestGenerator.class}) //TODO fails uncommenting this
@Singleton
public class DefaultAuthorizationResponseHandler implements AuthorizationResponseHandler {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultAuthorizationResponseHandler.class);

    private final AuthorizationCodeGrantRequestGenerator authorizationCodeGrantRequestGenerator;
    private final IdTokenAccessTokenResponseHandler idTokenAccessTokenResponseHandler;
    private final RxHttpClient tokenClient;

    private final @Nullable StateValidator stateValidator;

    /**
     * Creates a DefaultAuthorizationResponseHandler.
     * @param authorizationCodeGrantRequestGenerator Authorization Code Grant Request Generator
     * @param idTokenAccessTokenResponseHandler ID Token Access Token response handler
     * @param tokenClient RxHttpClient pointing to the token endpoint
     * @param stateValidator Authorization state parameter validator
     */
    public DefaultAuthorizationResponseHandler(AuthorizationCodeGrantRequestGenerator authorizationCodeGrantRequestGenerator,
                                               IdTokenAccessTokenResponseHandler idTokenAccessTokenResponseHandler,
                                               @Named("oauth2tokenendpoint") RxHttpClient tokenClient,
                                               @Nullable StateValidator stateValidator) {
        this.authorizationCodeGrantRequestGenerator = authorizationCodeGrantRequestGenerator;
        this.idTokenAccessTokenResponseHandler = idTokenAccessTokenResponseHandler;
        this.tokenClient = tokenClient;
        this.stateValidator = stateValidator;
    }

    @Override
    public Single<HttpResponse<?>> handle(HttpRequest originalRequest, AuthenticationResponse authenticationResponse) {

        if (stateValidator != null && authenticationResponse.getState() != null && !stateValidator.validate(originalRequest, authenticationResponse.getState())) {
            throw new InvalidStateException("state " + authenticationResponse.getState() + " is not valid");
        }

        HttpRequest request = authorizationCodeGrantRequestGenerator.generateRequest(authenticationResponse.getCode());
        try {
            Flowable<HttpResponse<IdTokenAccessTokenResponse>> flowable = tokenClient.exchange(request, IdTokenAccessTokenResponse.class);
            return flowable.map(response -> {
                Optional<IdTokenAccessTokenResponse> idTokenAccessTokenResponse = response.getBody();
                if (idTokenAccessTokenResponse.isPresent()) {
                    return idTokenAccessTokenResponseHandler.handle(originalRequest,
                            authenticationResponse,
                            idTokenAccessTokenResponse.get());
                }
                return HttpResponse.serverError();
            }).firstOrError();
        } catch (HttpClientResponseException e) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("http client exception: {}", request.getUri(), e);
            }
        }

        return Single.just(HttpResponse.serverError()); //TODO remove this
    }
}
