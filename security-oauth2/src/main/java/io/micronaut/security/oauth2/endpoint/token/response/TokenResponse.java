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
package io.micronaut.security.oauth2.endpoint.token.response;

import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import io.micronaut.core.annotation.Introspected;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;

import java.util.Calendar;
import java.util.Date;
import java.util.Optional;

/**
 * Represent the response of an authorization server to a valid access token request.
 *
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-5.1">RFC 6749 Access Token Successful Response</a>
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Introspected
@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy.class)
public class TokenResponse {
    @NonNull
    private String accessToken;

    @NonNull
    private String tokenType;

    @Nullable
    private Integer expiresIn;

    @Nullable
    private String refreshToken;

    @Nullable
    private String scope;

    @Nullable
    private Date expiresInDate;

    /**
     * Instantiates Access Token Response.
     */
    public TokenResponse() {

    }

    /**
     * Instantiates Access Token Response.
     * @param accessToken Access token issued by the authorization server.
     * @param tokenType The type of the token issued.
     */
    public TokenResponse(@NonNull String accessToken, @NonNull String tokenType) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
    }

    /**
     *
     * @return The access token issued by the authorization server.
     */
    @NonNull
    public String getAccessToken() {
        return accessToken;
    }

    /**
     *
     * @param accessToken The access token issued by the authorization server.
     */
    public void setAccessToken(@NonNull String accessToken) {
        this.accessToken = accessToken;
    }

    /**
     *
     * @return The type of the token issued.
     */
    @NonNull
    public String getTokenType() {
        return tokenType;
    }

    /**
     *
     * @param tokenType The type of the token issued.
     */
    public void setTokenType(@NonNull String tokenType) {
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
        if (expiresIn != null) {
            Calendar calendar = Calendar.getInstance();
            calendar.add(Calendar.SECOND, expiresIn);
            this.expiresInDate = calendar.getTime();
        }
    }

    /**
     *
     * @return Expiration date of the access token. Calculated with the {@link TokenResponse#expiresIn} received by the authorization server.
     */
    @NonNull
    public Optional<Date> getExpiresInDate() {
        return Optional.ofNullable(expiresInDate);
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

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        TokenResponse that = (TokenResponse) o;

        if (!accessToken.equals(that.accessToken)) {
            return false;
        }
        if (!tokenType.equals(that.tokenType)) {
            return false;
        }
        if (expiresIn != null ? !expiresIn.equals(that.expiresIn) : that.expiresIn != null) {
            return false;
        }
        if (refreshToken != null ? !refreshToken.equals(that.refreshToken) : that.refreshToken != null) {
            return false;
        }
        return scope != null ? scope.equals(that.scope) : that.scope == null;
    }

    @Override
    public int hashCode() {
        int result = accessToken.hashCode();
        result = 31 * result + tokenType.hashCode();
        result = 31 * result + (expiresIn != null ? expiresIn.hashCode() : 0);
        result = 31 * result + (refreshToken != null ? refreshToken.hashCode() : 0);
        result = 31 * result + (scope != null ? scope.hashCode() : 0);
        return result;
    }
}
