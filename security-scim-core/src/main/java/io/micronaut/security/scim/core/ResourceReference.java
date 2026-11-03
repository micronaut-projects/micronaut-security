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
 * A reference used for User group memberships and Group members.
 *
 * @param value The referenced SCIM resource identifier
 * @param ref The referenced SCIM resource URI
 * @param display The human-readable display name
 * @param type The membership derivation or referenced resource type
 * @since 5.4.0
 */
@Serdeable
@Experimental
public record ResourceReference(
    @Nullable String value,
    @JsonProperty("$ref") @Nullable String ref,
    @Nullable String display,
    @Nullable String type
) {
}
