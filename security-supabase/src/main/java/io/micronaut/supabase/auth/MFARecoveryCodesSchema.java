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
 * A freshly generated set of MFA recovery codes. Returned only by `POST /factors/recovery-codes` and `POST
 * /factors/recovery-codes/regenerate`; the codes cannot be retrieved afterwards.
 *
 * @param id ID of the user's `recovery_code` factor.
 * @param type Always `recovery_code`.
 * @param friendlyName The value for {@code friendlyName}.
 * @param total Number of codes in the set.
 * @param codes The plaintext single-use codes in canonical form (16 characters by default). Show them to the user
 *     once.
 * @since 5.5.1
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
