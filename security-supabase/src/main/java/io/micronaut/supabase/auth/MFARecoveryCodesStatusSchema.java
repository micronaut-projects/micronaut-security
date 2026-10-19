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
 * Enrollment status of a user's multi-factor recovery codes, as returned by {@code GET /factors/recovery-codes}.
 *
 * <p>Never contains code values. The server answers {@code 404} when the user has not enrolled recovery codes.</p>
 *
 * @param id Identifier of the user's {@code recovery_code} factor
 * @param type Factor type; always {@code recovery_code}
 * @param total Number of codes in the current set
 * @param remaining Number of codes in the current set that have not been redeemed
 * @since 0.0.1
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
