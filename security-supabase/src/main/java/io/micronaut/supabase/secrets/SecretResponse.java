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
package io.micronaut.supabase.secrets;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * A project secret as returned by {@code GET /v1/projects/{ref}/secrets}.
 *
 * <p>The value is returned in clear text, so responses must be handled with the same care as the secrets
 * themselves and never logged.</p>
 *
 * @param name Secret name, the environment variable name seen by Edge Functions
 * @param value Secret value
 * @param updatedAt Timestamp of the last update, absent for secrets never updated
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record SecretResponse(
    @NonNull @NotBlank String name,
    @NonNull @NotNull String value,
    @JsonProperty("updated_at") @Nullable String updatedAt
) {
}
