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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.Introspected;
import org.jspecify.annotations.Nullable;

/**
 * Represent the response of an authorization server to an invalid access token request.
 *
 * <p>The {@code error} member is exposed twice: {@link #getErrorCode()} returns the raw error code exactly as sent by
 * the authorization server, and {@link #getError()} returns it resolved to a {@link TokenError} constant
 * ({@link TokenError#UNKNOWN} when the code is not modelled).</p>
 *
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-5.2">RFC 6749 Access Token Error Response</a>
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Introspected
public class TokenErrorResponse {

    @Nullable
    private TokenError error;

    @Nullable
    private String errorCode;

    @Nullable
    private String errorDescription;

    @Nullable
    private String errorUri;

    /**
     * @return The error code resolved to a {@link TokenError}, {@link TokenError#UNKNOWN} if the code is not modelled, or {@code null} if the response carried no error code.
     */
    @Nullable
    @JsonIgnore
    public TokenError getError() {
        return error;
    }

    /**
     * Sets the error and the raw error code to the code of the supplied {@link TokenError}.
     * @param error The error code
     */
    @JsonIgnore
    public void setError(@Nullable TokenError error) {
        this.error = error;
        this.errorCode = error == null ? null : error.getErrorCode();
    }

    /**
     * @return The raw error code as returned by the authorization server, for example {@code invalid_grant} or a vendor specific code.
     * @since 5.4.0
     */
    @Nullable
    @JsonProperty("error")
    public String getErrorCode() {
        return errorCode;
    }

    /**
     * Sets the raw error code and resolves {@link #getError()} from it.
     * @param errorCode The raw error code as returned by the authorization server
     * @since 5.4.0
     */
    @JsonProperty("error")
    public void setErrorCode(@Nullable String errorCode) {
        this.errorCode = errorCode;
        this.error = errorCode == null ? null : TokenError.of(errorCode);
    }

    /**
     * @return The error description
     */
    @Nullable
    @JsonProperty("error_description")
    public String getErrorDescription() {
        return errorDescription;
    }

    /**
     * @param errorDescription The error description
     */
    @JsonProperty("error_description")
    public void setErrorDescription(String errorDescription) {
        this.errorDescription = errorDescription;
    }

    /**
     * @return The error uri
     */
    @Nullable
    @JsonProperty("error_uri")
    public String getErrorUri() {
        return errorUri;
    }

    /**
     * @param errorUri The error uri
     */
    @JsonProperty("error_uri")
    public void setErrorUri(String errorUri) {
        this.errorUri = errorUri;
    }

    @Override
    public String toString() {
        return "error: " + this.errorCode + ", errorDescription: " + this.errorDescription + ", errorUri: " + this.errorUri;
    }
}
