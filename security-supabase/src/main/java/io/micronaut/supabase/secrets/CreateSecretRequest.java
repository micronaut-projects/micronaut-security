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

import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;

/**
 * A secret to create, an item of the JSON array sent to {@code POST /v1/projects/{ref}/secrets}.
 *
 * <p>Creating a secret whose name already exists replaces its value. Names starting with
 * {@value #RESERVED_PREFIX} are reserved for the secrets Supabase injects itself, such as
 * {@code SUPABASE_URL}, and are rejected.</p>
 *
 * @param name Secret name of at most {@value #NAME_MAX_LENGTH} characters, not starting with
 *             {@value #RESERVED_PREFIX}
 * @param value Secret value of at most {@value #VALUE_MAX_LENGTH} characters
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record CreateSecretRequest(
    @NonNull @NotBlank @Size(max = CreateSecretRequest.NAME_MAX_LENGTH)
    @Pattern(regexp = CreateSecretRequest.NAME_PATTERN, message = "must not start with " + CreateSecretRequest.RESERVED_PREFIX)
    String name,
    @NonNull @NotNull @Size(max = CreateSecretRequest.VALUE_MAX_LENGTH) String value
) {
    /**
     * Prefix of the secret names Supabase reserves for itself.
     */
    public static final String RESERVED_PREFIX = "SUPABASE_";

    /**
     * Maximum length of a secret name.
     */
    public static final int NAME_MAX_LENGTH = 256;

    /**
     * Maximum length of a secret value.
     */
    public static final int VALUE_MAX_LENGTH = 24576;

    /**
     * Regular expression a secret name must match: anything not starting with {@value #RESERVED_PREFIX}.
     */
    public static final String NAME_PATTERN = "^(?!" + RESERVED_PREFIX + ").*";
}
