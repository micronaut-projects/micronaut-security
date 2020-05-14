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

package io.micronaut.security.errors;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * A single ASCII error code as described in Obtaining Authorization - Error Response seciton of OAuth 2.0 spec.
 *
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.1.2">Obtaining Authorization - Error Response</a>
 */
public enum ObtainingAuthorizationErrorCode implements ErrorCode {
    INVALID_REQUEST("invalid_request", "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."),
    UNAUTHORIZED_CLIENT("unauthorized_client", "The client is not authorized to request an authorization code using this method."),
    ACCESS_DENIED("access_denied", "The resource owner or authorization server denied the request."),
    UNSUPPORTED_RESPONSE_TYPE("unsupported_response_type", "The authorization server does not support obtaining an authorization code using this method."),
    INVALID_SCOPE("invalid_scope", "The requested scope is invalid, unknown, or malformed."),
    SERVER_ERROR("server_error", "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. (This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.)"),
    TEMPORARILY_UNAVAILABLE("temporarily_unavailable", "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server. (This error code is needed because a 503 Service Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.)");

    private String errorCode;
    private String errorCodeDescription;

    /**
     *
     * @param errorCode errorCode code
     * @param errorCodeDescription Human-readable ASCII [USASCII] text providing additional information, used to assist the client developer in understanding the errorCode that occurred.
     */
    ObtainingAuthorizationErrorCode(String errorCode, String errorCodeDescription) {
        this.errorCode = errorCode;
        this.errorCodeDescription = errorCodeDescription;
    }

    @Override
    public String getErrorCode() {
        return errorCode;
    }

    @Override
    public String getErrorCodeDescription() {
        return errorCodeDescription;
    }

    /**
     *
     * @return An errorCode code.
     */
    @Override
    @JsonValue
    public String toString() {
        return errorCode;
    }
}
