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

import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.validation.constraints.NotBlank;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * JSON body accepted by {@code POST /object/copy}.
 *
 * @param bucketId Bucket of the source object
 * @param sourceKey Key of the source object
 * @param sourceVersionId Version of the source object, defaults to the current one
 * @param destinationBucket Bucket of the copy, defaults to the source bucket
 * @param destinationKey Key of the copy
 * @param metadata Storage metadata to set on the copy
 * @param copyMetadata Whether to copy the user metadata of the source
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record CopyObjectRequest(
    @NonNull @NotBlank String bucketId,
    @NonNull @NotBlank String sourceKey,
    @Nullable String sourceVersionId,
    @Nullable String destinationBucket,
    @NonNull @NotBlank String destinationKey,
    @Nullable Metadata metadata,
    @Nullable Boolean copyMetadata
) {
    /**
     * Storage metadata of the copy.
     *
     * @param cacheControl {@code Cache-Control} value served with the copy
     * @param contentEncoding {@code Content-Encoding} value served with the copy
     * @param mimetype MIME type of the copy
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record Metadata(
        @Nullable String cacheControl,
        @Nullable String contentEncoding,
        @Nullable String mimetype
    ) {
    }
}
