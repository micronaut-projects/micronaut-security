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

/**
 * Open ID authentication error response codes.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#AuthError">Authentication Error Response</a>
 */
public enum AuthenticationErrorResponseCode {
    INVALID_REQUEST("invalid_request"),
    UNAUTHORIZED_CLIENT("unauthorized_client"),
    ACCESS_DENIED("access_denied"),
    UNSUPPORTED_RESPONSE_TYPE("unsupported_response_type"),
    INVALID_SCOPE("invalid_scope"),
    SERVER_ERROR("server_error"),
    TEMPORARILY_UNAVAILABLE("temporarily_unavailable"),
    INTERACTION_REQUIRED("interaction_required"),
    LOGIN_REQUIRED("login_required"),
    ACCOUNT_SELECTION_REQUIRED("account_selection_required"),
    CONSENT_REQUIRED("consent_required"),
    INVALID_REQUEST_URI("invalid_request_uri"),
    REQUEST_NOT_SUPPORTED("request_not_supported"),
    REQUEST_URI_NOT_SUPPORTED("request_uri_not_supported"),
    REGISTRATION_NOT_SUPPORTED("registration_not_supported");

    private String errorCode;

    /**
     *
     * @param errorCode errorCode code
     */
    AuthenticationErrorResponseCode(String errorCode) {
        this.errorCode = errorCode;
    }

    /**
     *
     * @return An errorCode code.
     */
    public String getError() {
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
