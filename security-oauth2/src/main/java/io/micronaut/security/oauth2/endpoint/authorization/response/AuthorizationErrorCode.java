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

import com.fasterxml.jackson.annotation.JsonValue;
import io.micronaut.security.errors.ErrorCode;

/**
 * Error codes for an Authentication Error Response message returned from the OP's Authorization Endpoint in response to the Authorization Request message sent by the RP.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#AuthError">Authentication Error Response</a>
 *
 * @since 2.0.0.
 */
public enum AuthorizationErrorCode implements ErrorCode {
    INTERACTION_REQUIRED("interaction_required", "The Authorization Server requires End-User interaction of some form to proceed. This error MAY be returned when the prompt parameter value in the Authentication Request is none, but the Authentication Request cannot be completed without displaying a user interface for End-User interaction."),
    LOGIN_REQUIRED("login_required", "The Authorization Server requires End-User authentication. This error MAY be returned when the prompt parameter value in the Authentication Request is none, but the Authentication Request cannot be completed without displaying a user interface for End-User authentication."),
    ACCOUNT_SELECTION_REQUIRED("account_selection_required", "The End-User is REQUIRED to select a session at the Authorization Server. The End-User MAY be authenticated at the Authorization Server with different associated accounts, but the End-User did not select a session. This error MAY be returned when the prompt parameter value in the Authentication Request is none, but the Authentication Request cannot be completed without displaying a user interface to prompt for a session to use."),
    CONSENT_REQUIRED("consent_required", "The Authorization Server requires End-User consent. This error MAY be returned when the prompt parameter value in the Authentication Request is none, but the Authentication Request cannot be completed without displaying a user interface for End-User consent."),
    INVALID_REQUEST_URI("invalid_request_uri", "The request_uri in the Authorization Request returns an error or contains invalid data."),
    INVALID_REQUEST_OBJECT("invalid_request_object", "The request parameter contains an invalid Request Object."),
    REQUEST_NOT_SUPPORTED("request_not_supported", "The OP does not support use of the request parameter defined in Section 6."),
    REQUEST_URI_NOT_SUPPORTED("request_uri_not_supported", "The OP does not support use of the request_uri parameter defined in Section 6."),
    REGISTRATION_NOT_SUPPORTED("registration_not_supported", "The OP does not support use of the registration parameter defined in Section 7.2.1."),
    // Section 4.1.2.1 of OAuth 2.0
    INVALID_REQUEST("invalid_request", "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."),
    UNAUTHORIZED_CLIENT("unauthorized_client", "The client is not authorized to request an authorization code using this method."),
    ACCESS_DENIED("access_denied", "The resource owner or authorization server denied the request."),
    UNSUPPORTED_RESPONSE_TYPE("unsupported_response_type", "The authorization server does not support obtaining an authorization code using this method."),
    INVALID_SCOPE("invalid_scope", "The requested scope is invalid, unknown, or malformed."),
    SERVER_ERROR("server_error", "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. (This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.)"),
    TEMPORARILY_UNAVAILABLE("temporarily_unavailable", "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server. (This error code is needed because a 503 Service Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.)"),
    // Sign in with LinkedIn
    UNAUTHORIZED_SCOPE_ERROR("unauthorized_scope_error", "Scope is not authorized for your application"),
    // Sign in with LinkedIn & Apple
    USER_CANCELLED_AUTHORIZE("user_cancelled_authorize", "The user cancelled the authorization");

    private String errorCode;
    private String errorCodeDescription;

    /**
     *
     * @param errorCode errorCode code
     * @param errorCodeDescription Human-readable ASCII [USASCII] text providing additional information, used to assist the client developer in understanding the errorCode that occurred.
     */
    AuthorizationErrorCode(String errorCode, String errorCodeDescription) {
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
