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

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;

/**
 * OAuth 2.0 Error Response.
 *
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.1.2">Obtaining Authorization - Error Response</a>
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
public interface ErrorResponse {

    String JSON_KEY_ERROR = "error";
    String JSON_KEY_STATE = "state";
    String JSON_KEY_ERROR_DESCRIPTION = "error_description";
    String JSON_KEY_ERROR_URI = "error_uri";

    /**
     *
     * @return The error code
     */
    @NonNull
    ErrorCode getError();

    /**
     *
     * @return Human-readable ASCII [USASCII] text providing additional information, used to assist the client developer in understanding the errorCode that occurred.
     */
    @Nullable
    String getErrorDescription();

    /**
     *
     * @return URI identifying a human-readable web page with information about the errorCode
     */
    @Nullable
    String getErrorUri();
}
