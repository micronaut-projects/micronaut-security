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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Oauth 2.0 ErrorCode Response.
 *
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-5.2">RFC 6749 - ErrorCode Response</a>
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public class Oauth2ErrorResponse {

    @Nonnull
    private String error;

    @Nullable
    private String errorDescription;

    @Nullable
    private String errorUri;

    @Nullable
    private String state;

    /**
     * Constructor.
     */
    public Oauth2ErrorResponse() {

    }

    /**
     * Althought the state is required if the Authorization Request included the state parameter. it is set to nullable because it is possible to send authorization requests without including a state.
     * @return OAuth 2.0 state value.
     */
    @Nullable
    public String getState() {
        return state;
    }

    /**
     *
     * @param state OAuth 2.0 state value.
     */
    public void setState(@Nullable String state) {
        this.state = state;
    }

    /**
     *
     * @return The error code
     */
    @Nonnull
    public String getError() {
        return error;
    }

    /**
     *
     * @param error The error code.
     */
    public void setError(String error) {
        this.error = error;
    }

    /**
     *
     * @return Human-readable ASCII [USASCII] text providing additional information, used to assist the client developer in
     *  understanding the errorCode that occurred.
     */
    @Nullable
    public String getErrorDescription() {
        return errorDescription;
    }


    /**
     *
      * @param errorDescription Human-readable ASCII [USASCII] text providing additional information about the errorCode.
     */
    public void setErrorDescription(@Nullable String errorDescription) {
        this.errorDescription = errorDescription;
    }

    /**
     *
     * @return URI identifying a human-readable web page with information about the errorCode
     */
    @Nullable
    public String getErrorUri() {
        return errorUri;
    }

    /**
     *
     * @param errorUri URI identifying a human-readable web page with information about the errorCode.
     */
    public void setErrorUri(@Nullable String errorUri) {
        this.errorUri = errorUri;
    }

    @Override
    public String toString() {
        return "Oauth2ErrorResponse{" +
                "error='" + error + '\'' +
                ", errorDescription='" + errorDescription + '\'' +
                ", errorUri='" + errorUri + '\'' +
                '}';
    }

    /**
     * Instantiates a {@link Oauth2ErrorResponse} from a {@link ErrorResponse}.
     * @param errorResponse Error Response
     * @return A {@link Oauth2ErrorResponse}
     */
    public static Oauth2ErrorResponse of(ErrorResponse errorResponse) {
        Oauth2ErrorResponse oauth2ErrorResponse = new Oauth2ErrorResponse();
        oauth2ErrorResponse.setError(errorResponse.getError());
        oauth2ErrorResponse.setErrorDescription(errorResponse.getErrorDescription());
        oauth2ErrorResponse.setState(errorResponse.getState());
        oauth2ErrorResponse.setErrorUri(errorResponse.getErrorUri());
        return oauth2ErrorResponse;
    }
}
