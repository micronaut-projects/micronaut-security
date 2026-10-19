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
 * JSON body accepted by {@code POST /bucket}.
 *
 * @param name Bucket name
 * @param id Bucket identifier, defaults to the name
 * @param isPublic Whether objects can be read without credentials through the public routes
 * @param type Bucket type, {@code STANDARD} or {@code ANALYTICS}
 * @param versioningStatus Object versioning status, {@code DISABLED} or {@code ENABLED}; versioning must be
 *                         enabled on the server
 * @param fileSizeLimit Maximum object size: a number of bytes, or a string with a unit such as {@code 10MB}
 * @param allowedMimeTypes MIME types accepted for uploads, for example {@code image/png}
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record CreateBucketRequest(
    @NonNull @NotBlank String name,
    @Nullable String id,
    @JsonProperty("public") @Nullable Boolean isPublic,
    @Nullable String type,
    @JsonProperty("versioning_status") @Nullable String versioningStatus,
    @JsonProperty("file_size_limit") @Nullable Object fileSizeLimit,
    @JsonProperty("allowed_mime_types") @Nullable List<String> allowedMimeTypes
) {
}
