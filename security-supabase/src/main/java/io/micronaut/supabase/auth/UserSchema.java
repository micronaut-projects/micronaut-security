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
 * Object describing the user related to the issued access and refresh tokens.
 *
 * @param id The value for {@code id}.
 * @param aud The value for {@code aud}.
 * @param role The value for {@code role}.
 * @param email User's primary contact email. In most cases you can uniquely identify a user by their email
 *     address, but not in all cases.
 * @param emailConfirmedAt The value for {@code emailConfirmedAt}.
 * @param phone User's primary contact phone number. In most cases you can uniquely identify a user by their phone
 *     number, but not in all cases.
 * @param phoneConfirmedAt The value for {@code phoneConfirmedAt}.
 * @param confirmationSentAt The value for {@code confirmationSentAt}.
 * @param confirmedAt The value for {@code confirmedAt}.
 * @param recoverySentAt The value for {@code recoverySentAt}.
 * @param newEmail The value for {@code newEmail}.
 * @param emailChangeSentAt The value for {@code emailChangeSentAt}.
 * @param newPhone The value for {@code newPhone}.
 * @param phoneChangeSentAt The value for {@code phoneChangeSentAt}.
 * @param reauthenticationSentAt The value for {@code reauthenticationSentAt}.
 * @param lastSignInAt The value for {@code lastSignInAt}.
 * @param appMetadata The value for {@code appMetadata}.
 * @param userMetadata The value for {@code userMetadata}.
 * @param factors The value for {@code factors}.
 * @param identities The value for {@code identities}.
 * @param bannedUntil The value for {@code bannedUntil}.
 * @param createdAt The value for {@code createdAt}.
 * @param updatedAt The value for {@code updatedAt}.
 * @param deletedAt The value for {@code deletedAt}.
 * @param isAnonymous The value for {@code isAnonymous}.
 * @since 5.5.1
 */
@Serdeable
@Experimental
public record UserSchema(
    @Nullable String id,
    @Nullable String aud,
    @Nullable String role,
    @Nullable String email,
    @JsonProperty("email_confirmed_at") @Nullable String emailConfirmedAt,
    @Nullable String phone,
    @JsonProperty("phone_confirmed_at") @Nullable String phoneConfirmedAt,
    @JsonProperty("confirmation_sent_at") @Nullable String confirmationSentAt,
    @JsonProperty("confirmed_at") @Nullable String confirmedAt,
    @JsonProperty("recovery_sent_at") @Nullable String recoverySentAt,
    @JsonProperty("new_email") @Nullable String newEmail,
    @JsonProperty("email_change_sent_at") @Nullable String emailChangeSentAt,
    @JsonProperty("new_phone") @Nullable String newPhone,
    @JsonProperty("phone_change_sent_at") @Nullable String phoneChangeSentAt,
    @JsonProperty("reauthentication_sent_at") @Nullable String reauthenticationSentAt,
    @JsonProperty("last_sign_in_at") @Nullable String lastSignInAt,
    @JsonProperty("app_metadata") @Nullable Map<String, Object> appMetadata,
    @JsonProperty("user_metadata") @Nullable Map<String, Object> userMetadata,
    @Nullable List<MFAFactorSchema> factors,
    @Nullable List<IdentitySchema> identities,
    @JsonProperty("banned_until") @Nullable String bannedUntil,
    @JsonProperty("created_at") @Nullable String createdAt,
    @JsonProperty("updated_at") @Nullable String updatedAt,
    @JsonProperty("deleted_at") @Nullable String deletedAt,
    @JsonProperty("is_anonymous") @Nullable Boolean isAnonymous
) {
}
