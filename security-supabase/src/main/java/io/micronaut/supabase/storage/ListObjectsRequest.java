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
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * JSON body accepted by {@code POST /object/list/{bucketName}}.
 *
 * @param prefix Folder to list, empty for the bucket root; always sent because the server requires it
 * @param exactMatch Whether to return only the object whose key equals the prefix
 * @param limit Maximum number of objects, defaults to 100
 * @param offset Number of objects to skip
 * @param sortBy Sort column and order
 * @param search Text the object names must contain
 * @param noncurrentVersions Whether to {@code exclude}, {@code include} or return {@code only} noncurrent versions
 * @param deleteMarkers Whether to {@code exclude}, {@code include} or return {@code only} delete markers
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record ListObjectsRequest(
    @JsonInclude(JsonInclude.Include.ALWAYS) @NonNull @NotNull String prefix,
    @Nullable Boolean exactMatch,
    @Nullable Integer limit,
    @Nullable Integer offset,
    @Nullable SortBy sortBy,
    @Nullable String search,
    @Nullable String noncurrentVersions,
    @Nullable String deleteMarkers
) {
    /**
     * Sort order of a listing.
     *
     * @param column {@code name}, {@code updated_at}, {@code created_at} or, for the v1 listing,
     *               {@code last_accessed_at}
     * @param order {@code asc} or {@code desc}
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record SortBy(
        @NonNull @NotBlank String column,
        @Nullable String order
    ) {
    }
}
