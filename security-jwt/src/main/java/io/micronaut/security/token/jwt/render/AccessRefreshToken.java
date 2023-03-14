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
package io.micronaut.security.token.jwt.render;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.serde.annotation.Serdeable;

import jakarta.validation.constraints.NotBlank;

/**
 * Stores the combination of access and refresh tokens.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Serdeable
public class AccessRefreshToken {

    @JsonProperty("access_token")
    @NonNull
    @NotBlank
    private final String accessToken;

    @JsonProperty("refresh_token")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @Nullable
    private final String refreshToken;

    @JsonProperty("token_type")
    @NonNull
    @NotBlank
    private final String tokenType;

    @JsonProperty("expires_in")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @Nullable
    private Integer expiresIn;

    /**
     *
     * @param accessToken JWT token
     * @param refreshToken JWT token
     * @param tokenType Type of token
     * @param expiresIn Seconds until token expiration
     */
    public AccessRefreshToken(@NonNull String accessToken,
                              @Nullable String refreshToken,
                              @NonNull String tokenType,
                              @Nullable Integer expiresIn) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.tokenType = tokenType;
        this.expiresIn = expiresIn;
    }

    /**
     * accessToken getter.
     * @return The access token
     */
    @NonNull
    public String getAccessToken() {
        return accessToken;
    }

    /**
     * refreshToken getter.
     * @return The refresh token
     */
    @Nullable
    public String getRefreshToken() {
        return refreshToken;
    }

    /**
     * token type getter.
     * @return TokenType e.g. Bearer
     */
    @NonNull
    public String getTokenType() {
        return tokenType;
    }

    /**
     * lifetime in seconds of the access token getter.
     * @return expiration time
     */
    @Nullable
    public Integer getExpiresIn() {
        return expiresIn;
    }
}
