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
 * A single ASCII error code as described in Issuing an Access Token - Error Response section of OAuth 2.0 spec.
 *
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-5.2">Issuing Access Token - Error Response</a>
 *
 * @author Sergio del Amo
 * @since 2.0.0
 */
public enum  IssuingAnAccessTokenErrorCode implements ErrorCode {
    INVALID_REQUEST("invalid_request", "The request is missing a required parameter, includes an unsupported parameter value (other than grant type), repeats a parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the client, or is otherwise malformed."),
    INVALID_CLIENT("invalid_client", "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The authorization server MAY return an HTTP 401 (Unauthorized) status code to indicate which HTTP authentication schemes are supported.  If the client attempted to authenticate via the \"Authorization\" request header field, the authorization server MUST respond with an HTTP 401 (Unauthorized) status code and include the \"WWW-Authenticate\" response header field matching the authentication scheme used by the client."),
    INVALID_GRANT("invalid_grant", "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client."),
    UNAUTHORIZED_CLIENT("unauthorized_client", "The authenticated client is not authorized to use this authorization grant type."),
    UNSUPPORTED_GRANT_TYPE("unsupported_grant_type", "The authorization grant type is not supported by the authorization server.");


    private String errorCode;
    private String errorCodeDescription;

    /**
     *
     * @param errorCode errorCode code
     * @param errorCodeDescription Human-readable ASCII [USASCII] text providing additional information, used to assist the client developer in understanding the errorCode that occurred.
     */
    IssuingAnAccessTokenErrorCode(String errorCode, String errorCodeDescription) {
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
