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
 * Supabase Auth user account.
 *
 * <p>Returned by the {@code /user} and {@code /admin/users} routes and embedded in
 * {@link AccessTokenResponseSchema}. Administrators also send this record as the body of
 * {@code PUT /admin/users/{userId}}; only the non-null fields are applied. Timestamps use RFC 3339
 * format.</p>
 *
 * @param id User identifier, a UUID
 * @param aud Audience claim placed in the user's tokens
 * @param role Role claim placed in the user's tokens, typically {@code authenticated}
 * @param email Primary email address; unique among users of the same audience
 * @param emailConfirmedAt Timestamp at which the email address was confirmed
 * @param phone Primary phone number in E.164 format; unique among users of the same audience
 * @param phoneConfirmedAt Timestamp at which the phone number was confirmed
 * @param confirmationSentAt Timestamp at which the last confirmation message was sent
 * @param confirmedAt Timestamp at which either the email or the phone was confirmed
 * @param recoverySentAt Timestamp at which the last password recovery message was sent
 * @param newEmail Email address awaiting confirmation after an email change
 * @param emailChangeSentAt Timestamp at which the last email change message was sent
 * @param newPhone Phone number awaiting confirmation after a phone change
 * @param phoneChangeSentAt Timestamp at which the last phone change message was sent
 * @param reauthenticationSentAt Timestamp at which the last reauthentication nonce was sent
 * @param lastSignInAt Timestamp of the most recent sign-in
 * @param appMetadata Metadata managed by the application through admin APIs; not editable by the user
 * @param userMetadata Metadata the user may edit through {@code PUT /user}
 * @param factors Multi-factor authentication factors enrolled by the user
 * @param identities Identities linked to the user
 * @param bannedUntil Timestamp until which the user is banned from signing in
 * @param createdAt Creation timestamp
 * @param updatedAt Last modification timestamp
 * @param deletedAt Soft-deletion timestamp
 * @param isAnonymous Whether the user was created through anonymous sign-in
 * @since 0.0.1
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
