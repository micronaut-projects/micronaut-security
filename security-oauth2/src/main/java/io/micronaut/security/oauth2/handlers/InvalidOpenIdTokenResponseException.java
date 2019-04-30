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

import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;

/**
 * A runtime exception thrown when the validation of a {@link OpenIdTokenResponse} fails.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
public class InvalidOpenIdTokenResponseException extends RuntimeException {

    private final OpenIdTokenResponse response;

    /**
     * Constructor.
     *
     * @param response ID Token - Access Token response obtained from the Token endpoint.
     */
    public InvalidOpenIdTokenResponseException(OpenIdTokenResponse response) {
        this.response = response;
    }

    /**
     *
     * @return The {@link OpenIdTokenResponse} which failed validation.
     */
    public OpenIdTokenResponse getResponse() {
        return response;
    }
}
