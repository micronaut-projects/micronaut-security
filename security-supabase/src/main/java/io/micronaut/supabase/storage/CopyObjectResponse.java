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
 * JSON body returned by {@code POST /object/copy}: the upload identifiers followed by the copied object.
 *
 * @param objectId Identifier of the copy, the same value as {@code id}
 * @param key Key of the copy prefixed with the bucket name
 * @param name Key of the copy within the bucket
 * @param bucketId Bucket of the copy
 * @param owner Legacy owner column
 * @param ownerId Identifier of the user who made the copy
 * @param version Identifier of the current version of the copy
 * @param id Identifier of the copy
 * @param updatedAt Last modification timestamp
 * @param createdAt Creation timestamp
 * @param lastAccessedAt Last access timestamp
 * @param metadata Storage metadata such as {@code size}, {@code mimetype} and {@code eTag}
 * @param userMetadata Metadata copied from the source when requested
 * @param archivedAt Timestamp at which the version stopped being current
 * @param isDeleteMarker Whether the version is a delete marker
 * @param isVersioned Whether the copy lives in a versioned bucket
 * @param buckets Bucket of the copy, when the server joins it
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record CopyObjectResponse(
    @JsonProperty("Id") @Nullable String objectId,
    @JsonProperty("Key") @NonNull @NotBlank String key,
    @Nullable String name,
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
    @Nullable BucketSchema buckets
) {
}
