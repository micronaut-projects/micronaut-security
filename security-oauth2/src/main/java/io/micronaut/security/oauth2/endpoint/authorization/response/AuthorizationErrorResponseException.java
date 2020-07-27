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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A runtime exception thrown when a Oauth 2. Error code is received from the authorization endpoint.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
public class AuthorizationErrorResponseException extends RuntimeException {

    private static final Logger LOG = LoggerFactory.getLogger(AuthorizationErrorResponseException.class);

    private final AuthorizationErrorResponse authorizationErrorResponse;

    /**
     * Constructor.
     *
     * @param error OAuth 2.0 Authentication Error Response.
     */
    public AuthorizationErrorResponseException(AuthorizationErrorResponse error) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("error: {} error_description: {}, state: {} error_uri {}",
                    error.getError(),
                    error.getErrorDescription() != null ? error.getErrorDescription() : "",
                    error.getErrorUri() != null ? error.getErrorUri() : "",
                    error.getState() != null ? error.getState() : "");
        }
        this.authorizationErrorResponse = error;
    }

    /**
     *
     * @return Authentication Error Response.
     */
    public AuthorizationErrorResponse getAuthorizationErrorResponse() {
        return authorizationErrorResponse;
    }
}
