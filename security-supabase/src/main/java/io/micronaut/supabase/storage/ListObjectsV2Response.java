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
package io.micronaut.supabase.storage;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.validation.constraints.NotNull;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * JSON body returned by {@code POST /object/list-v2/{bucketName}}.
 *
 * @param folders Folders below the prefix, when a delimiter was requested; their name ends with a slash
 * @param objects Objects below the prefix
 * @param hasNext Whether another page exists
 * @param nextCursor Cursor of the next page
 * @param nextCursorKey Key the next page starts at
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record ListObjectsV2Response(
    @JsonInclude(JsonInclude.Include.ALWAYS) @NonNull @NotNull List<ObjectSchema> folders,
    @JsonInclude(JsonInclude.Include.ALWAYS) @NonNull @NotNull List<ObjectSchema> objects,
    @NonNull @NotNull Boolean hasNext,
    @Nullable String nextCursor,
    @Nullable String nextCursorKey
) {
}
