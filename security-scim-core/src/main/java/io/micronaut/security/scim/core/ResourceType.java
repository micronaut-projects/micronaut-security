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
import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * RFC 7643 resource-type discovery resource.
 *
 * @since 5.4.0
 */
@Serdeable
@Experimental
public final class ResourceType extends ScimResource {
    @Nullable
    @NotBlank
    private String name;
    @Nullable
    private String description;
    @Nullable
    @NotBlank
    private String endpoint;
    @Nullable
    @NotBlank
    private String schema;
    @Nullable
    private List<@Valid SchemaExtension> schemaExtensions;

    /**
     * Creates a resource type with its RFC 7643 schema URI.
     *
     * @since 5.4.0
     */
    public ResourceType() {
        super(SchemaUris.RESOURCE_TYPE);
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The resource type name
     * @since 5.4.0
     */
    @Nullable
    public String getName() {
        return name;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param name The resource type name
     * @since 5.4.0
     */
    public void setName(@Nullable String name) {
        this.name = name;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The human-readable resource type description
     * @since 5.4.0
     */
    @Nullable
    public String getDescription() {
        return description;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param description The human-readable resource type description
     * @since 5.4.0
     */
    public void setDescription(@Nullable String description) {
        this.description = description;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The resource endpoint relative to the service provider base URL
     * @since 5.4.0
     */
    @Nullable
    public String getEndpoint() {
        return endpoint;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param endpoint The resource endpoint relative to the service provider base URL
     * @since 5.4.0
     */
    public void setEndpoint(@Nullable String endpoint) {
        this.endpoint = endpoint;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The resource type's primary schema URI
     * @since 5.4.0
     */
    @Nullable
    public String getSchema() {
        return schema;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param schema The resource type's primary schema URI
     * @since 5.4.0
     */
    public void setSchema(@Nullable String schema) {
        this.schema = schema;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The resource type's supported schema extensions
     * @since 5.4.0
     */
    @Nullable
    public List<SchemaExtension> getSchemaExtensions() {
        return schemaExtensions;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param schemaExtensions The resource type's supported schema extensions
     * @since 5.4.0
     */
    public void setSchemaExtensions(@Nullable List<SchemaExtension> schemaExtensions) {
        this.schemaExtensions = schemaExtensions;
    }
}
