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

import io.micronaut.security.oauth2.endpoint.authorization.state.State;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * OAuth 2.0 Error Response.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#AuthError">Authentication Error Response</a>
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
public interface AuthorizationErrorResponse {

    String JSON_KEY_ERROR = "error";
    String JSON_KEY_STATE = "state";
    String JSON_KEY_ERROR_DESCRIPTION = "error_description";
    String JSON_KEY_ERROR_URI = "error_uri";

    /**
     *
     * @return The error code
     */
    @Nonnull
    AuthorizationError getError();

    /**
     *
     * @return Human-readable ASCII [USASCII] text providing additional information, used to assist the client developer in understanding the errorCode that occurred.
     */
    @Nullable
    String getErrorDescription();

    /**
     * Although the state is required if the Authorization Request included the state parameter. it is set to nullable because it is possible to send authorization requests without including a state.
     * @return OAuth 2.0 state value.
     */
    @Nullable
    State getState();

    /**
     *
     * @return URI identifying a human-readable web page with information about the errorCode
     */
    @Nullable
    String getErrorUri();
}
