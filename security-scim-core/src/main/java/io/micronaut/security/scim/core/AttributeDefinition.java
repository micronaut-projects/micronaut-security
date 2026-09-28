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
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * Definition and characteristics of a SCIM attribute.
 *
 * @param name The attribute name
 * @param type The attribute data type
 * @param subAttributes Definitions of complex sub-attributes
 * @param multiValued Whether the attribute is multi-valued
 * @param description The human-readable description
 * @param required Whether the attribute is required
 * @param canonicalValues Suggested canonical values
 * @param caseExact Whether string comparisons are case-sensitive
 * @param mutability The attribute mutability
 * @param returned The attribute return rule
 * @param uniqueness The uniqueness scope
 * @param referenceTypes Resource types accepted by a reference attribute
 * @since 5.4.0
 */
@Serdeable
@Experimental
public record AttributeDefinition(
    @NotBlank String name,
    @NotNull AttributeType type,
    @Nullable List<@Valid AttributeDefinition> subAttributes,
    boolean multiValued,
    @Nullable String description,
    boolean required,
    @Nullable List<String> canonicalValues,
    boolean caseExact,
    @NotNull Mutability mutability,
    @NotNull Returned returned,
    @NotNull Uniqueness uniqueness,
    @Nullable List<String> referenceTypes
) {
}
