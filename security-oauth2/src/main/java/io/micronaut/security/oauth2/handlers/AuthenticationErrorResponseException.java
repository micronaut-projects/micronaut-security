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

import io.micronaut.security.oauth2.responses.ErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A runtime exception thrown when a Oauth 2. Error code is received from the authorization endpoint.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
public class AuthenticationErrorResponseException extends RuntimeException {

    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationErrorResponseException.class);

    private final ErrorResponse errorResponse;

    /**
     * Constructor.
     *
     * @param errorResponse OAuth 2.0 Authentication Error Response.
     */
    public AuthenticationErrorResponseException(ErrorResponse errorResponse) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("error: {} error_description: {}, state: {} error_uri {}",
                    errorResponse.getError(),
                    errorResponse.getErrorDescription() != null ? errorResponse.getErrorDescription() : "",
                    errorResponse.getErrorUri() != null ? errorResponse.getErrorUri() : "",
                    errorResponse.getState() != null ? errorResponse.getState() : "");
        }
        this.errorResponse = errorResponse;
    }

    /**
     *
     * @return Authentication Error Response.
     */
    public ErrorResponse getErrorResponse() {
        return errorResponse;
    }
}
