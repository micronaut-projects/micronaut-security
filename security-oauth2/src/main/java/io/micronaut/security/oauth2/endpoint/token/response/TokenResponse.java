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
 * Represent the response of an authorization server to a valid access token request.
 *
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-5.1>RFC 6749 Access Token Successful Response</a>
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Introspected
@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy.class)
public class TokenResponse {

    private String accessToken;
    private String tokenType;
    private Integer expiresIn;
    private String refreshToken;
    private String scope;

    /**
     * Instantiates Access Token Response.
     */
    public TokenResponse() {

    }

    /**
     *
     * @return The access token issued by the authorization server.
     */
    @Nonnull
    public String getAccessToken() {
        return accessToken;
    }

    /**
     *
     * @param accessToken The access token issued by the authorization server.
     */
    public void setAccessToken(@Nonnull String accessToken) {
        this.accessToken = accessToken;
    }

    /**
     *
     * @return The type of the token issued.
     */
    @Nonnull
    public String getTokenType() {
        return tokenType;
    }

    /**
     *
     * @param tokenType The type of the token issued.
     */
    public void setTokenType(@Nonnull String tokenType) {
        this.tokenType = tokenType;
    }

    /**
     *
     * @return The lifetime in seconds of the access token.
     */
    @Nullable
    public Integer getExpiresIn() {
        return expiresIn;
    }

    /**
     *
     * @param expiresIn The lifetime in seconds of the access token.
     */
    public void setExpiresIn(@Nullable Integer expiresIn) {
        this.expiresIn = expiresIn;
    }

    /**
     *
     * @return Scope of the access token.
     */
    @Nullable
    public String getScope() {
        return scope;
    }

    /**
     *
     * @param scope Scope of the access token.
     */
    public void setScope(@Nullable String scope) {
        this.scope = scope;
    }

    /**
     *
     * @return The refresh token, which can be used to obtain new access tokens using the same authorization grant.
     */
    @Nullable
    public String getRefreshToken() {
        return refreshToken;
    }

    /**
     *
     * @param refreshToken The refresh token, which can be used to obtain new access tokens using the same authorization grant.
     */
    public void setRefreshToken(@Nullable String refreshToken) {
        this.refreshToken = refreshToken;
    }

}
