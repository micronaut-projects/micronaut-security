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

import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import io.micronaut.supabase.storage.ListObjectsRequest.SortBy;
import org.jspecify.annotations.Nullable;

/**
 * JSON body accepted by {@code POST /object/list-v2/{bucketName}}, the cursor-based listing.
 *
 * @param prefix Key prefix to list
 * @param exactMatch Whether to return only the object whose key equals the prefix
 * @param limit Maximum number of entries per page
 * @param cursor Cursor returned by the previous page
 * @param withDelimiter Whether to group keys below the prefix into folders
 * @param sortBy Sort column and order
 * @param noncurrentVersions Whether to {@code exclude}, {@code include} or return {@code only} noncurrent versions
 * @param deleteMarkers Whether to {@code exclude}, {@code include} or return {@code only} delete markers
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record ListObjectsV2Request(
    @Nullable String prefix,
    @Nullable Boolean exactMatch,
    @Nullable Integer limit,
    @Nullable String cursor,
    @JsonProperty("with_delimiter") @Nullable Boolean withDelimiter,
    @Nullable SortBy sortBy,
    @Nullable String noncurrentVersions,
    @Nullable String deleteMarkers
) {
}
