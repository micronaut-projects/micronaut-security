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

/**
 * JSON body returned after an upload through {@code POST} or {@code PUT /object/{bucketName}/{key}} and
 * {@code PUT /object/upload/sign/{bucketName}/{key}}.
 *
 * @param id Object identifier; absent for uploads through a signed URL
 * @param key Object key prefixed with the bucket name, for example {@code avatars/alice.png}
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record UploadObjectResponse(
    @JsonProperty("Id") @Nullable String id,
    @JsonProperty("Key") @NonNull @NotBlank String key
) {
}
