package io.micronaut.security.oauth2.handlers;

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

import io.micronaut.security.oauth2.openid.idtoken.IdTokenAccessTokenResponse;

/**
 * A runtime exception thrown when the validation of a {@link IdTokenAccessTokenResponse} fails.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
public class InvalidIdTokenAccessTokenResponseException extends RuntimeException {

    private final IdTokenAccessTokenResponse response;
    /**
     * Sets the message based on the response.
     *
     * @param response The authentication response
     */
    public InvalidIdTokenAccessTokenResponseException(IdTokenAccessTokenResponse response) {
        this.response = response;
    }

    public IdTokenAccessTokenResponse getResponse() {
        return response;
    }
}
