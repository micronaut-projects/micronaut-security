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

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.openid.idtoken.IdTokenAccessTokenResponse;
import io.micronaut.security.oauth2.openid.idtoken.IdTokenAccessTokenResponseValidator;

import javax.inject.Singleton;
import java.util.Optional;

/**
 * Validates a {@link IdTokenAccessTokenResponse} and creates an HTTP Response.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Requires(beans = {
        IdTokenAccessTokenResponseValidator.class,
        SuccessfulIdTokenAccessTokenResponseHandler.class
})
@Singleton
public class DefaultIdTokenAccessTokenResponseHandler implements IdTokenAccessTokenResponseHandler {

    private final IdTokenAccessTokenResponseValidator idTokenAccessTokenResponseValidator;
    private final SuccessfulIdTokenAccessTokenResponseHandler successfulIdTokenAccessTokenResponseHandler;

    /**
     *
     * @param idTokenAccessTokenResponseValidator ID Token Access token response validator
     * @param successfulIdTokenAccessTokenResponseHandler Successful - ID Token Access token handler
     */
    public DefaultIdTokenAccessTokenResponseHandler(IdTokenAccessTokenResponseValidator idTokenAccessTokenResponseValidator,              SuccessfulIdTokenAccessTokenResponseHandler successfulIdTokenAccessTokenResponseHandler) {
        this.idTokenAccessTokenResponseValidator = idTokenAccessTokenResponseValidator;
        this.successfulIdTokenAccessTokenResponseHandler = successfulIdTokenAccessTokenResponseHandler;
    }

    @Override
    public HttpResponse<?> handle(HttpRequest<?> request, IdTokenAccessTokenResponse idTokenAccessTokenResponse) {
        Optional<Authentication> authenticationOptional = idTokenAccessTokenResponseValidator.validate(idTokenAccessTokenResponse);

        if (authenticationOptional.isPresent()) {
            return successfulIdTokenAccessTokenResponseHandler.handle(request, idTokenAccessTokenResponse, authenticationOptional.get());
        }
        throw new InvalidIdTokenAccessTokenResponseException(idTokenAccessTokenResponse);
    }
}
