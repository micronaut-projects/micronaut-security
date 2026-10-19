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
import jakarta.validation.constraints.NotBlank;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.Map;

/**
 * A storage object as returned by the listing, bulk deletion and copy routes.
 *
 * <p>{@code POST /object/list/{bucketName}} returns the name relative to the searched prefix, while
 * {@code POST /object/list-v2/{bucketName}} returns the full key as the name and folders with a trailing
 * slash and null identifiers.</p>
 *
 * @param name Object name
 * @param bucketId Bucket the object belongs to
 * @param owner Legacy owner column
 * @param ownerId Identifier of the user who uploaded the object
 * @param version Identifier of the current version
 * @param id Object identifier
 * @param updatedAt Last modification timestamp
 * @param createdAt Creation timestamp
 * @param lastAccessedAt Last access timestamp
 * @param metadata Storage metadata such as {@code size}, {@code mimetype}, {@code eTag} and {@code cacheControl}
 * @param userMetadata Metadata supplied by the uploader
 * @param archivedAt Timestamp at which the version stopped being current, for noncurrent versions
 * @param isDeleteMarker Whether the version is a delete marker
 * @param isVersioned Whether the object lives in a versioned bucket
 * @param key Full object key, returned by the v2 listing
 * @param buckets Bucket of the object, when the server joins it
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record ObjectSchema(
    @NonNull @NotBlank String name,
    @JsonProperty("bucket_id") @Nullable String bucketId,
    @Nullable String owner,
    @JsonProperty("owner_id") @Nullable String ownerId,
    @Nullable String version,
    @Nullable String id,
    @JsonProperty("updated_at") @Nullable String updatedAt,
    @JsonProperty("created_at") @Nullable String createdAt,
    @JsonProperty("last_accessed_at") @Nullable String lastAccessedAt,
    @Nullable Map<String, Object> metadata,
    @JsonProperty("user_metadata") @Nullable Map<String, Object> userMetadata,
    @JsonProperty("archived_at") @Nullable String archivedAt,
    @JsonProperty("is_delete_marker") @Nullable Boolean isDeleteMarker,
    @JsonProperty("is_versioned") @Nullable Boolean isVersioned,
    @Nullable String key,
    @Nullable BucketSchema buckets
) {
}
