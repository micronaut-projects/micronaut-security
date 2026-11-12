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
package io.micronaut.security.scim.core;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.validation.constraints.PositiveOrZero;

/**
 * SCIM bulk operation configuration.
 *
 * @param supported Whether bulk operations are supported
 * @param maxOperations The maximum operations per request
 * @param maxPayloadSize The maximum request size in bytes
 * @since 5.4.0
 */
@Serdeable
@Experimental
public record BulkFeature(
    boolean supported,
    @PositiveOrZero int maxOperations,
    @PositiveOrZero int maxPayloadSize
) {
}
