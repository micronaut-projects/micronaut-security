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
 * Default sub-attributes for a complex multi-valued SCIM attribute.
 *
 * @param value The attribute's significant value
 * @param type A label describing the value's function
 * @param primary Whether this is the preferred value
 * @param display A human-readable display value
 * @param ref A reference URI associated with the value
 * @since 5.4.0
 */
@Serdeable
@Experimental
public record MultiValuedAttribute(
    @Nullable String value,
    @Nullable String type,
    @Nullable Boolean primary,
    @Nullable String display,
    @JsonProperty("$ref") @Nullable String ref
) {
}
