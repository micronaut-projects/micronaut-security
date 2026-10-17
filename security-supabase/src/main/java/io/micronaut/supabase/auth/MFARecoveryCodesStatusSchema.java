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

import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import org.jspecify.annotations.Nullable;

/**
 * Enrollment status of the user's MFA recovery codes. Never contains code values.
 *
 * @param id ID of the user's `recovery_code` factor.
 * @param type Always `recovery_code`.
 * @param total Number of codes in the current set.
 * @param remaining Number of codes in the current set that have not been used yet.
 * @since 5.5.1
 */
@Serdeable
@Experimental
public record MFARecoveryCodesStatusSchema(
    @Nullable String id,
    @Nullable String type,
    @Nullable Integer total,
    @Nullable Integer remaining
) {
}
