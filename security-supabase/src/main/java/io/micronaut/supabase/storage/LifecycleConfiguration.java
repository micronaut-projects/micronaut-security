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

import com.fasterxml.jackson.annotation.JsonInclude;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Map;

/**
 * Lifecycle configuration of a bucket, exchanged by {@code GET} and {@code PUT /bucket/{bucketId}/lifecycle}.
 *
 * <p>Lifecycle rules expire noncurrent object versions and require versioning and the lifecycle feature to be
 * enabled on the server; otherwise the routes answer with the code {@code FeatureNotEnabled}. A {@code PUT}
 * replaces the whole configuration.</p>
 *
 * @param rules Lifecycle rules
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record LifecycleConfiguration(
    @NonNull @NotNull List<@Valid Rule> rules
) {
    /**
     * A lifecycle rule.
     *
     * @param id Rule identifier, assigned by the server when absent
     * @param status {@code Enabled} or {@code Disabled}
     * @param filter Objects the rule applies to; only the empty filter, every object, is supported in v1, and it
     *               is always sent because the server requires it
     * @param noncurrentVersionExpiration Expiration of noncurrent versions
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record Rule(
        @Nullable String id,
        @NonNull @NotBlank String status,
        @JsonInclude(JsonInclude.Include.ALWAYS) @NonNull @NotNull Map<String, Object> filter,
        @NonNull @NotNull @Valid NoncurrentVersionExpiration noncurrentVersionExpiration
    ) {
    }

    /**
     * Expiration of noncurrent object versions.
     *
     * @param noncurrentDays Days after which a version that is no longer current is deleted
     * @param newerNoncurrentVersions Number of newer noncurrent versions to retain regardless of age
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record NoncurrentVersionExpiration(
        @NonNull @NotNull Integer noncurrentDays,
        @Nullable Integer newerNoncurrentVersions
    ) {
    }
}
