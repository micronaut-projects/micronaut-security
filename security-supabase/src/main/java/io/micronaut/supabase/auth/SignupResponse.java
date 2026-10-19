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
import java.util.Map;

/**
 * Body returned by {@code POST /signup} when the signup immediately creates a session.
 *
 * <p>This happens when email or phone confirmation is disabled or auto-confirmed. When confirmation is
 * required, Supabase Auth instead returns the user object alone, without session fields.
 * {@link SupabaseAuthClient#signup} therefore exposes the body as a map so both forms can be handled;
 * bind that map to this record when a session is expected.</p>
 *
 * @param accessToken JWT access token
 * @param tokenType Token type; currently always {@code bearer}
 * @param expiresIn Number of seconds until the access token expires
 * @param expiresAt Unix epoch seconds at which the access token expires
 * @param refreshToken Opaque single-use refresh token
 * @param providerToken Access token issued by an external provider, when one was involved
 * @param providerRefreshToken Refresh token issued by an external provider, when one was involved
 * @param user The newly created user
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record SignupResponse(
    @JsonProperty("access_token") @Nullable String accessToken,
    @JsonProperty("token_type") @Nullable String tokenType,
    @JsonProperty("expires_in") @Nullable Long expiresIn,
    @JsonProperty("expires_at") @Nullable Long expiresAt,
    @JsonProperty("refresh_token") @Nullable String refreshToken,
    @JsonProperty("provider_token") @Nullable String providerToken,
    @JsonProperty("provider_refresh_token") @Nullable String providerRefreshToken,
    @Nullable User user
) {
    /**
     * User fields returned by signup.
     *
     * <p>A subset of {@link UserSchema} that is stable across signup response forms.</p>
     *
     * @param id User identifier, a UUID
     * @param aud Audience claim placed in the user's tokens
     * @param role Role claim placed in the user's tokens, typically {@code authenticated}
     * @param email Email address, when the user signed up with one
     * @param phone Phone number, when the user signed up with one
     * @param appMetadata Metadata managed by the application through admin APIs; not editable by the user
     * @param userMetadata Metadata supplied by the user at signup
     * @param identities Identities linked to the user
     * @param createdAt Creation timestamp in RFC 3339 format
     * @param updatedAt Last modification timestamp in RFC 3339 format
     * @param confirmedAt Timestamp at which either the email or the phone was confirmed
     * @param emailConfirmedAt Timestamp at which the email address was confirmed
     * @param phoneConfirmedAt Timestamp at which the phone number was confirmed
     * @param confirmationSentAt Timestamp at which the confirmation message was sent
     * @param lastSignInAt Timestamp of the most recent sign-in
     * @param isAnonymous Whether the user was created through anonymous sign-in
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record User(
        @Nullable String id,
        @Nullable String aud,
        @Nullable String role,
        @Nullable String email,
        @Nullable String phone,
        @JsonProperty("app_metadata") @Nullable Map<String, Object> appMetadata,
        @JsonProperty("user_metadata") @Nullable Map<String, Object> userMetadata,
        @Nullable List<Map<String, Object>> identities,
        @JsonProperty("created_at") @Nullable String createdAt,
        @JsonProperty("updated_at") @Nullable String updatedAt,
        @JsonProperty("confirmed_at") @Nullable String confirmedAt,
        @JsonProperty("email_confirmed_at") @Nullable String emailConfirmedAt,
        @JsonProperty("phone_confirmed_at") @Nullable String phoneConfirmedAt,
        @JsonProperty("confirmation_sent_at") @Nullable String confirmationSentAt,
        @JsonProperty("last_sign_in_at") @Nullable String lastSignInAt,
        @JsonProperty("is_anonymous") @Nullable Boolean isAnonymous
    ) {
    }
}
