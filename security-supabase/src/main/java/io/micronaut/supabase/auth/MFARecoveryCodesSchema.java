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
 * Freshly generated set of multi-factor recovery codes.
 *
 * <p>Returned only by {@code POST /factors/recovery-codes} and {@code POST /factors/recovery-codes/regenerate}.
 * The plaintext codes cannot be retrieved afterwards, so show them to the user once. Each code can be
 * redeemed a single time through {@code POST /factors/recovery-codes/verify}.</p>
 *
 * @param id Identifier of the user's {@code recovery_code} factor
 * @param type Factor type; always {@code recovery_code}
 * @param friendlyName Name displayed for the recovery-code factor
 * @param total Number of codes in the set
 * @param codes Plaintext single-use codes in canonical form, 16 characters each by default
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record MFARecoveryCodesSchema(
    @Nullable String id,
    @Nullable String type,
    @JsonProperty("friendly_name") @Nullable String friendlyName,
    @Nullable Integer total,
    @Nullable List<String> codes
) {
}
