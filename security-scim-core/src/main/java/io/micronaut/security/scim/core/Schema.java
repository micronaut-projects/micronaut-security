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
import jakarta.validation.constraints.NotEmpty;
import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * RFC 7643 Schema discovery resource.
 *
 * @since 5.4.0
 */
@Serdeable
@Experimental
public final class Schema extends ScimResource {
    @Nullable
    private String name;
    @Nullable
    private String description;
    @Nullable
    @NotEmpty
    private List<@Valid AttributeDefinition> attributes;

    /**
     * Creates a Schema resource with its RFC 7643 schema URI.
     *
     * @since 5.4.0
     */
    public Schema() {
        super(SchemaUris.SCHEMA);
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The unique schema URI
     * @since 5.4.0
     */
    @Override
    @Nullable
    @NotBlank
    public String getId() {
        return super.getId();
    }

    /**
     * Sets the unique schema URI used as this resource's identifier.
     *
     * @param id The schema URI
     * @since 5.4.0
     */
    @Override
    public void setId(@Nullable String id) {
        super.setId(id);
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The schema's human-readable name
     * @since 5.4.0
     */
    @Nullable
    public String getName() {
        return name;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param name The schema's human-readable name
     * @since 5.4.0
     */
    public void setName(@Nullable String name) {
        this.name = name;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The schema's human-readable description
     * @since 5.4.0
     */
    @Nullable
    public String getDescription() {
        return description;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param description The schema's human-readable description
     * @since 5.4.0
     */
    public void setDescription(@Nullable String description) {
        this.description = description;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The attributes defined by the schema
     * @since 5.4.0
     */
    @Nullable
    public List<AttributeDefinition> getAttributes() {
        return attributes;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param attributes The attributes defined by the schema
     * @since 5.4.0
     */
    public void setAttributes(@Nullable List<AttributeDefinition> attributes) {
        this.attributes = attributes;
    }
}
