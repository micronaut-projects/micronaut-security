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
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.jspecify.annotations.Nullable;

/**
 * Persistent representation of a custom SCIM resource extension.
 *
 * <p>{@code extensionJson} contains only the extension object, not the entire
 * resource. It is deliberately stored as text so the entity is portable across
 * JDBC databases; database migrations should choose a text, CLOB, or native
 * JSON column appropriate for the target database.</p>
 *
 * @param id The database-generated row identifier
 * @param resourceType The owning resource type
 * @param resourceId The owning resource identifier
 * @param schemaUri The extension schema URI and JSON property name
 * @param extensionJson The serialized JSON extension object
 * @since 5.4.0
 */
@MappedEntity("scim_resource_extension")
@Index(
    name = "scim_resource_extension_uk",
    columns = {"resource_type", "resource_id", "schema_uri"},
    unique = true
)
@Experimental
public record ScimResourceExtensionEntity(
    @Id @GeneratedValue @Nullable Long id,
    @NotNull ScimResourceType resourceType,
    @NotBlank String resourceId,
    @NotBlank String schemaUri,
    @NotBlank String extensionJson
) {
}
