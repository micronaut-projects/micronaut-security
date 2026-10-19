/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.supabase.auth;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import org.jspecify.annotations.Nullable;
import java.util.List;

/**
 * Session issued by Supabase Auth after a successful authentication.
 *
 * <p>Returned by {@code POST /token}, {@code POST /verify}, {@code POST /factors/{factorId}/verify} and
 * {@code POST /factors/recovery-codes/verify}. The access token is a JWT signed with the project's
 * JWT secret or signing key; the refresh token is opaque and single use.</p>
 *
 * @param accessToken JWT access token that expires after {@code expiresIn} seconds
 * @param refreshToken Opaque single-use token that obtains a new access and refresh token through the
 *                     {@code refresh_token} grant
 * @param tokenType Token type; currently always {@code bearer}
 * @param expiresIn Number of seconds until the access token expires
 * @param expiresAt Unix epoch seconds at which the access token expires
 * @param weakPassword Present only for the {@code password} grant when the password used is weak
 * @param user The user the tokens were issued for
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record AccessTokenResponseSchema(
    @JsonProperty("access_token") @Nullable String accessToken,
    @JsonProperty("refresh_token") @Nullable String refreshToken,
    @JsonProperty("token_type") @Nullable String tokenType,
    @JsonProperty("expires_in") @Nullable Integer expiresIn,
    @JsonProperty("expires_at") @Nullable Integer expiresAt,
    @JsonProperty("weak_password") @Nullable WeakPassword weakPassword,
    @Nullable UserSchema user
) {
    /**
     * Warning that the password used to sign in does not meet the project's password policy.
     *
     * <p>The session is still issued. Applications typically prompt the user to choose a stronger
     * password.</p>
     *
     * @param reasons Policy violations, such as {@code length}, {@code characters} or {@code pwned}
     * @param message Human-readable explanation of why the password is weak
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record WeakPassword(
        @Nullable List<String> reasons,
        @Nullable String message
    ) {
    }
}
