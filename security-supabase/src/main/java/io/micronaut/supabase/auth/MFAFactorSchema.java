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
 * Represents a MFA factor.
 *
 * @param id The value for {@code id}.
 * @param status Usually one of: - verified - unverified
 * @param friendlyName The value for {@code friendlyName}.
 * @param factorType Usually one of: - totp - phone - webauthn - recovery_code
 * @param webauthnCredential The value for {@code webauthnCredential}.
 * @param phone The value for {@code phone}.
 * @param createdAt The value for {@code createdAt}.
 * @param updatedAt The value for {@code updatedAt}.
 * @param lastChallengedAt The value for {@code lastChallengedAt}.
 * @since 5.5.1
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
