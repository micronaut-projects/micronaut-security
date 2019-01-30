/*
 * Copyright 2017-2018 original authors
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

/**
 * ErrorCode Response parameters defined in Section 4.1.2.1 of OAuth 2.0.
 *
 * Oauth 2.0
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.1.2">ErrorCode Response</a>
 * @author Sergio del Amo
 * @since 1.0.0
 */
public enum ErrorCode {

    INVALID_REQUEST("invalid_request"),
    UNAUTHORIZED_CLIENT("unauthorized_client"),
    ACCESS_DENIED("access_denied"),
    UNSUPPORTED_RESPONSE_TYPE("unsupported_response_type"),
    INVALID_SCOPE("invalid_scope"),
    SERVER_ERROR("server_error"),
    TEMPORARILY_UNAVAILABLE("temporarily_unavailable");

    private String errorCode;

    /**
     *
     * @param errorCode ErrorCode code
     */
    ErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }

    /**
     *
     * @return An errorCode code.
     */
    public String getErrorCode() {
        return errorCode;
    }

    /**
     *
     * @param errorCode the errorCode code
     */
    public void setErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }
}
