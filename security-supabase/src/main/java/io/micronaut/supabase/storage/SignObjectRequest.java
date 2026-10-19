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
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * JSON body accepted by {@code POST /object/sign/{bucketName}/{key}}.
 *
 * @param expiresIn Seconds the signed URL stays valid
 * @param transform Image transformation to apply when the URL is served
 * @param versionId Version to sign, defaults to the current one
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record SignObjectRequest(
    @NonNull @NotNull @Positive Integer expiresIn,
    @Nullable TransformOptions transform,
    @Nullable String versionId
) {
}
