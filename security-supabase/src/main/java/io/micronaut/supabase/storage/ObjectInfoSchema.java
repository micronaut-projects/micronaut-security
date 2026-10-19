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
import org.jspecify.annotations.Nullable;

import java.util.Map;

/**
 * Object metadata as returned by the {@code GET /object/info/**} routes.
 *
 * <p>The OpenAPI document does not describe this body; the fields follow the running server.</p>
 *
 * @param id Object identifier
 * @param name Object key within the bucket
 * @param version Identifier of the version described
 * @param bucketId Bucket the object belongs to
 * @param size Size in bytes
 * @param contentType MIME type given at upload
 * @param cacheControl {@code Cache-Control} value served with the object
 * @param contentEncoding {@code Content-Encoding} value served with the object
 * @param etag Entity tag, quoted
 * @param metadata Metadata supplied by the uploader
 * @param lastModified Last modification timestamp
 * @param createdAt Creation timestamp
 * @param archivedAt Timestamp at which the version stopped being current
 * @param isDeleteMarker Whether the version is a delete marker
 * @param isVersioned Whether the object lives in a versioned bucket
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record ObjectInfoSchema(
    @Nullable String id,
    @Nullable String name,
    @Nullable String version,
    @JsonProperty("bucket_id") @Nullable String bucketId,
    @Nullable Long size,
    @JsonProperty("content_type") @Nullable String contentType,
    @JsonProperty("cache_control") @Nullable String cacheControl,
    @JsonProperty("content_encoding") @Nullable String contentEncoding,
    @Nullable String etag,
    @Nullable Map<String, Object> metadata,
    @JsonProperty("last_modified") @Nullable String lastModified,
    @JsonProperty("created_at") @Nullable String createdAt,
    @JsonProperty("archived_at") @Nullable String archivedAt,
    @JsonProperty("is_delete_marker") @Nullable Boolean isDeleteMarker,
    @JsonProperty("is_versioned") @Nullable Boolean isVersioned
) {
}
