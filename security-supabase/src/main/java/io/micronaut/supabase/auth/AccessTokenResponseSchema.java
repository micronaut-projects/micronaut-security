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
 * Models the AccessTokenResponseSchema object in Supabase Auth.
 *
 * @param accessToken A valid JWT that will expire in `expires_in` seconds.
 * @param refreshToken An opaque string that can be used once to obtain a new access and refresh token.
 * @param tokenType What type of token this is. Only `bearer` returned, may change in the future.
 * @param expiresIn Number of seconds after which the `access_token` should be renewed by using the refresh token with
 *     the `refresh_token` grant type.
 * @param expiresAt UNIX timestamp after which the `access_token` should be renewed by using the refresh token with
 *     the `refresh_token` grant type.
 * @param weakPassword Only returned on the `/token?grant_type=password` endpoint. When present, it indicates that the
 *     password used is weak. Inspect the `reasons` and/or `message` properties to identify why.
 * @param user The value for {@code user}.
 * @since 5.5.1
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
     * Only returned on the `/token?grant_type=password` endpoint. When present, it indicates that the password
     * used is weak. Inspect the `reasons` and/or `message` properties to identify why.
     *
     * @param reasons The value for {@code reasons}.
     * @param message The value for {@code message}.
     * @since 5.5.1
     */
    @Serdeable
    @Experimental
    public record WeakPassword(
        @Nullable List<String> reasons,
        @Nullable String message
    ) {
    }
}
