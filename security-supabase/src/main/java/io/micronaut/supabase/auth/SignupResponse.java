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
 * The GoTrue signup response when signup creates a session.
 *
 * <p>When email or phone confirmation is required, GoTrue instead returns a
 * user object without session fields. {@link SupabaseAuthClient} therefore
 * exposes its response body as a map to preserve both response forms.</p>
 *
 * @param accessToken JWT access token
 * @param tokenType Token type, typically {@code bearer}
 * @param expiresIn Access token lifetime in seconds
 * @param expiresAt Access token expiration as Unix epoch seconds
 * @param refreshToken Refresh token
 * @param providerToken Provider access token, when supplied by an external provider
 * @param providerRefreshToken Provider refresh token, when supplied by an external provider
 * @param user Created Supabase Auth user
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
     * Supabase Auth user data returned by signup.
     *
     * @param id User identifier
     * @param aud User audience
     * @param role User role
     * @param email User email address
     * @param phone User phone number
     * @param appMetadata Supabase-managed application metadata
     * @param userMetadata User metadata provided during signup
     * @param identities Linked identity records
     * @param createdAt User creation timestamp
     * @param updatedAt User update timestamp
     * @param confirmedAt User confirmation timestamp
     * @param emailConfirmedAt Email confirmation timestamp
     * @param phoneConfirmedAt Phone confirmation timestamp
     * @param confirmationSentAt Confirmation message timestamp
     * @param lastSignInAt Last sign-in timestamp
     * @param isAnonymous Whether the user is anonymous
     */
    @Serdeable
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
