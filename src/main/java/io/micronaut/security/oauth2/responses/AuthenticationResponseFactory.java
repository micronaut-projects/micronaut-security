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

package io.micronaut.security.oauth2.responses;

import io.micronaut.http.HttpParameters;
import io.micronaut.security.oauth2.handlers.AuthenticationErrorResponseException;
import io.micronaut.security.oauth2.openid.endpoints.authorization.state.StateSerDes;

import javax.annotation.Nullable;
import javax.inject.Singleton;
import java.util.Map;


/**
 * AuthenticationResponse Factory which ease creation of {@link AuthenticationResponse} objects given a {@link Map} or a {@link HttpParameters}.
 *
 * @since 1.0.0
 * @author Sergio del Amo
 */
@Singleton
public class AuthenticationResponseFactory {

    private final StateSerDes stateSerDes;

    /**
     * @param stateSerDes The state serdes
     */
    public AuthenticationResponseFactory(StateSerDes stateSerDes) {
        this.stateSerDes = stateSerDes;
    }

    /**
     *
     * @param parameters Http parameters
     * @return null or a populated AuthenticationResponse
     * @throws AuthenticationErrorResponseException if the response was an error response
     */
    @Nullable
    public AuthenticationResponse create(HttpParameters parameters) throws AuthenticationErrorResponseException {
        if (ErrorResponseDetector.isErrorResponse(parameters)) {
            ErrorResponse errorResponse = new ErrorResponseHttpParamsAdapter(parameters);
            throw new AuthenticationErrorResponseException(errorResponse);

        } else if (AuthorizationResponseDetector.isAuthorizationResponse(parameters)) {
            return new AuthenticationResponseHttpParamsAdapter(parameters, stateSerDes);
        }
        return null;
    }

    /**
     *
     * @param formFields A map containing a payload typically send with application/x-www-form-urlencoded POST request.
     * @return null or a populated AuthenticationResponse
     * @throws AuthenticationErrorResponseException if the response was an error response
     */
    @Nullable
    public AuthenticationResponse create(Map<String, String> formFields) throws AuthenticationErrorResponseException {
        if (ErrorResponseDetector.isErrorResponse(formFields)) {
            ErrorResponse errorResponse = new ErrorResponseMapAdapter(formFields);
            throw new AuthenticationErrorResponseException(errorResponse);

        } else if (AuthorizationResponseDetector.isAuthorizationResponse(formFields)) {
            return new AuthenticationResponseMapAdapter(formFields, stateSerDes);
        }
        return null;
    }
}
