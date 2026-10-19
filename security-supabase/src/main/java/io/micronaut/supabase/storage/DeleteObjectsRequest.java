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
import jakarta.validation.constraints.NotEmpty;
import org.jspecify.annotations.NonNull;

import java.util.List;

/**
 * JSON body accepted by {@code DELETE /object/{bucketName}}.
 *
 * <p>The server also accepts objects with {@code path} and {@code versionId} in place of plain keys to delete
 * a single version; this record models the plain keys, which delete the current version.</p>
 *
 * @param prefixes Keys of the objects to delete
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record DeleteObjectsRequest(
    @NonNull @NotEmpty List<String> prefixes
) {
}
