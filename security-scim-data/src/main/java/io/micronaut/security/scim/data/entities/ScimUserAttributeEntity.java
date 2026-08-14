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
package io.micronaut.security.scim.data.entities;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.data.annotation.GeneratedValue;
import io.micronaut.data.annotation.Id;
import io.micronaut.data.annotation.Index;
import io.micronaut.data.annotation.MappedEntity;
import io.micronaut.data.annotation.MappedProperty;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.jspecify.annotations.Nullable;

/**
 * Persistent entry in one of the RFC 7643 multi-valued User attributes.
 *
 * @param id The database-generated row identifier
 * @param userId The owning User identifier
 * @param attributeKind The multi-valued User attribute represented by this row
 * @param value The attribute value
 * @param type The attribute value type, such as {@code work} or {@code home}
 * @param primaryValue Whether this is the primary value for its attribute
 * @param display The human-readable display value
 * @param referenceUri The URI referenced by the value
 * @param position The stable position used when reconstructing the SCIM array
 * @since 5.4.0
 */
@MappedEntity("scim_user_attribute")
@Index(name = "scim_user_attribute_owner_idx", columns = {"user_id", "attribute_kind"})
@Experimental
public record ScimUserAttributeEntity(
    @Id @GeneratedValue @Nullable Long id,
    @NotBlank String userId,
    @NotNull ScimUserAttributeKind attributeKind,
    @Nullable @MappedProperty("attribute_value") String value,
    @Nullable @MappedProperty("attribute_type") String type,
    @Nullable Boolean primaryValue,
    @Nullable String display,
    @Nullable String referenceUri,
    @Min(0) int position
) {
}
