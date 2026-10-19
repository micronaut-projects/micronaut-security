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

/**
 * Multi-factor authentication factor enrolled by a user.
 *
 * <p>A factor starts as {@code unverified} after enrollment and becomes {@code verified} once the user
 * completes a challenge. Sessions that verify a factor are upgraded to authenticator assurance level
 * {@code aal2}.</p>
 *
 * @param id Factor identifier used in {@code /factors/{factorId}} routes
 * @param status Verification status, either {@code verified} or {@code unverified}
 * @param friendlyName User-chosen name that distinguishes the factor, unique per user
 * @param factorType Factor type: {@code totp}, {@code phone}, {@code webauthn} or {@code recovery_code}
 * @param webauthnCredential Credential descriptor of a {@code webauthn} factor
 * @param phone Phone number of a {@code phone} factor in E.164 format
 * @param createdAt Creation timestamp in RFC 3339 format
 * @param updatedAt Last modification timestamp in RFC 3339 format
 * @param lastChallengedAt Timestamp of the most recent challenge in RFC 3339 format
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record MFAFactorSchema(
    @Nullable String id,
    @Nullable String status,
    @JsonProperty("friendly_name") @Nullable String friendlyName,
    @JsonProperty("factor_type") @Nullable String factorType,
    @JsonProperty("webauthn_credential") @Nullable String webauthnCredential,
    @Nullable String phone,
    @JsonProperty("created_at") @Nullable String createdAt,
    @JsonProperty("updated_at") @Nullable String updatedAt,
    @JsonProperty("last_challenged_at") @Nullable String lastChallengedAt
) {
}
