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
package io.micronaut.security.oauth2.endpoint.token.response;

import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import io.micronaut.core.annotation.Introspected;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Represent the response of an authorization server to an invalid access token request.
 *
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-5.2>RFC 6749 Access Token Error Response</a>
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Introspected
@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy.class)
public class TokenErrorResponse {

    private TokenError error;
    private String errorDescription;
    private String errorUri;

    /**
     * Default constructor
     */
    public TokenErrorResponse() {
    }

    /**
     * @return The error code
     */
    @Nonnull
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
}
