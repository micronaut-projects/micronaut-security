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

import java.util.List;

/**
 * A storage bucket as returned by {@code GET /bucket} and {@code GET /bucket/{bucketId}}.
 *
 * @param id Bucket identifier, equal to the name unless an id was given at creation
 * @param name Bucket name
 * @param owner Legacy owner column, empty for buckets created with a service key
 * @param ownerId Identifier of the user who created the bucket
 * @param isPublic Whether objects can be read without credentials through the public routes
 * @param type Bucket type, {@code STANDARD} or {@code ANALYTICS}
 * @param versioningStatus Object versioning status, {@code DISABLED}, {@code ENABLED} or {@code SUSPENDED}
 * @param fileSizeLimit Maximum object size in bytes, or {@code null} for the project-wide limit
 * @param allowedMimeTypes MIME types accepted for uploads, or {@code null} for any
 * @param createdAt Creation timestamp
 * @param updatedAt Last modification timestamp
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record BucketSchema(
    @NonNull @NotBlank String id,
    @NonNull @NotBlank String name,
    @Nullable String owner,
    @JsonProperty("owner_id") @Nullable String ownerId,
    @JsonProperty("public") @Nullable Boolean isPublic,
    @Nullable String type,
    @JsonProperty("versioning_status") @Nullable String versioningStatus,
    @JsonProperty("file_size_limit") @Nullable Long fileSizeLimit,
    @JsonProperty("allowed_mime_types") @Nullable List<String> allowedMimeTypes,
    @JsonProperty("created_at") @Nullable String createdAt,
    @JsonProperty("updated_at") @Nullable String updatedAt
) {
}
