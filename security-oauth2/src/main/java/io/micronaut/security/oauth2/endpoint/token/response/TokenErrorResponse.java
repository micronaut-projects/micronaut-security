/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.oauth2.endpoint.token.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.Introspected;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;

/**
 * Represent the response of an authorization server to an invalid access token request.
 *
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-5.2">RFC 6749 Access Token Error Response</a>
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Introspected
public class TokenErrorResponse {

    @NonNull
    private TokenError error;

    @JsonProperty("error_description")
    @Nullable
    private String errorDescription;

    @JsonProperty("error_uri")
    @Nullable
    private String errorUri;

    /**
     * @return The error code
     */
    @NonNull
    public TokenError getError() {
        return error;
    }

    /**
     * @param error The error code
     */
    public void setError(TokenError error) {
        this.error = error;
    }

    /**
     * @return The error description
     */
    @Nullable
    public String getErrorDescription() {
        return errorDescription;
    }

    /**
     * @param errorDescription The error description
     */
    public void setErrorDescription(String errorDescription) {
        this.errorDescription = errorDescription;
    }

    /**
     * @return The error uri
     */
    @Nullable
    public String getErrorUri() {
        return errorUri;
    }

    /**
     * @param errorUri The error uri
     */
    public void setErrorUri(String errorUri) {
        this.errorUri = errorUri;
    }

    @Override
    public String toString() {
        return "error: " + this.error.toString() + ", errorDescription: " + this.errorDescription + ", errorUri: " + this.errorUri;
    }
}
