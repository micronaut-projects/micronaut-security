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

import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import org.jspecify.annotations.Nullable;

/**
 * The manager reference in the enterprise User extension.
 *
 * @param value The manager's User resource identifier
 * @param ref The manager's User resource URI
 * @param displayName The manager's display name
 * @since 5.4.0
 */
@Serdeable
@Experimental
public record Manager(
    @Nullable String value,
    @JsonProperty("$ref") @Nullable String ref,
    @Nullable String displayName
) {
}
