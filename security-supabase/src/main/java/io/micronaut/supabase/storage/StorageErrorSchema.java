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

/**
 * Error body returned by Supabase Storage for a rejected request.
 *
 * <p>The server answers most rejected requests with HTTP status {@code 400} regardless of the cause and
 * places the status that describes the cause in {@code statusCode}, for example {@code 404} with code
 * {@code NoSuchKey} for a missing object or {@code 409} with code {@code KeyAlreadyExists} for an upload
 * without upsert. Branch on {@code code}, which is stable, rather than on {@code message}.</p>
 *
 * @param statusCode Status describing the cause, as a string such as {@code 404}
 * @param error Short error name such as {@code not_found} or {@code Unauthorized}
 * @param message Human-readable description of the problem
 * @param code Stable machine-readable code such as {@code NoSuchBucket}, {@code NoSuchKey},
 *             {@code KeyAlreadyExists}, {@code AccessDenied}, {@code InvalidMimeType} or {@code FeatureNotEnabled}
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record StorageErrorSchema(
    @NonNull @NotBlank String statusCode,
    @NonNull @NotBlank String error,
    @NonNull @NotBlank String message,
    @NonNull @NotBlank String code
) {
}
