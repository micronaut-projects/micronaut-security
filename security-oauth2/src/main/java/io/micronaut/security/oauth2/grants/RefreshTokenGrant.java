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
package io.micronaut.security.oauth2.grants;

import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import io.micronaut.core.annotation.Introspected;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Refresh Token Grant.
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-6">Refreshing an Access Token</a>
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Introspected
@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy.class)
public class RefreshTokenGrant {

    private String grantType = GrantType.REFRESH_TOKEN.toString();
    private String refreshToken;
    private String scope;

    /**
     * Default constructor.
     */
    public RefreshTokenGrant() {

    }

    /**
     *
     * @return refresh_token
     */
    @NonNull
    public String getGrantType() {
        return grantType;
    }

    /**
     *
     * @return requested scope values for the new access token.
     */
    @Nullable
    public String getScope() {
        return scope;
    }

    /**
     *
     * @param scope requested scope values for the new access token.
     */
    public void setScope(@Nullable String scope) {
        this.scope = scope;
    }

    /**
     *
     * @return The refresh token issued to the client.
     */
    @NonNull
    public String getRefreshToken() {
        return refreshToken;
    }

    /**
     *
     * @param refreshToken The refresh token issued to the client.
     */
    public void setRefreshToken(@NonNull String refreshToken) {
        this.refreshToken = refreshToken;
    }
}
