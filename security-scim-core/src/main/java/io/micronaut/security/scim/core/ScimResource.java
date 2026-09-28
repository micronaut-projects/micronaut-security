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

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import io.micronaut.core.annotation.Experimental;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Common attributes and extension support shared by SCIM resources.
 *
 * @since 5.4.0
 */
@Experimental
public abstract class ScimResource {
    private final String primarySchema;

    @NotEmpty
    private List<@NotBlank String> schemas;

    @Nullable
    private String id;

    @Nullable
    private String externalId;

    @Nullable
    @Valid
    private Meta meta;

    private final Map<String, Object> extensions = new LinkedHashMap<>();

    /**
     * Creates a resource with its required primary schema URI.
     *
     * @param primarySchema The resource's primary schema URI
     */
    protected ScimResource(String primarySchema) {
        this.primarySchema = requireAbsoluteUri(primarySchema);
        this.schemas = new ArrayList<>(List.of(primarySchema));
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The schema URIs that define the resource
     * @since 5.4.0
     */
    public List<String> getSchemas() {
        return Collections.unmodifiableList(schemas);
    }

    /**
     * Replaces the schema URI list. Values must be unique and include the primary schema.
     *
     * @param schemas The schema URIs
     * @since 5.4.0
     */
    public void setSchemas(List<String> schemas) {
        Objects.requireNonNull(schemas, "schemas");
        if (schemas.isEmpty()) {
            throw new IllegalArgumentException("schemas must not be empty");
        }
        List<String> validated = schemas.stream().map(ScimResource::requireAbsoluteUri).toList();
        if (new HashSet<>(validated).size() != validated.size()) {
            throw new IllegalArgumentException("schemas must not contain duplicate values");
        }
        if (!validated.contains(primarySchema)) {
            throw new IllegalArgumentException("schemas must contain the primary schema " + primarySchema);
        }
        this.schemas = new ArrayList<>(validated);
    }

    /**
     * Adds an extension schema URI if it is not already present.
     *
     * @param schema The extension schema URI
     * @since 5.4.0
     */
    public void addSchema(String schema) {
        String validated = requireAbsoluteUri(schema);
        if (!schemas.contains(validated)) {
            schemas.add(validated);
        }
    }

    /**
     * Removes an extension schema URI. The primary schema cannot be removed.
     *
     * @param schema The extension schema URI
     * @return {@code true} when an extension schema was removed
     * @since 5.4.0
     */
    public boolean removeSchema(String schema) {
        if (primarySchema.equals(schema)) {
            return false;
        }
        extensions.remove(schema);
        return schemas.remove(schema);
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The service-provider-issued resource identifier, if assigned
     * @since 5.4.0
     */
    @Nullable
    public String getId() {
        return id;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param id The service-provider-issued resource identifier
     * @since 5.4.0
     */
    public void setId(@Nullable String id) {
        this.id = id;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The provisioning-client-issued identifier, if assigned
     * @since 5.4.0
     */
    @Nullable
    public String getExternalId() {
        return externalId;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param externalId The provisioning-client-issued identifier
     * @since 5.4.0
     */
    public void setExternalId(@Nullable String externalId) {
        this.externalId = externalId;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return Resource metadata, if assigned
     * @since 5.4.0
     */
    @Nullable
    public Meta getMeta() {
        return meta;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param meta Resource metadata
     * @since 5.4.0
     */
    public void setMeta(@Nullable Meta meta) {
        this.meta = meta;
    }

    /**
     * Returns custom schema extension objects. Entries are flattened into the resource JSON object.
     *
     * @return Custom extension values keyed by schema URI
     * @since 5.4.0
     */
    @JsonAnyGetter
    public Map<String, Object> getExtensions() {
        return Collections.unmodifiableMap(extensions);
    }

    /**
     * Adds, replaces, or removes a custom schema extension object.
     *
     * @param schema The extension schema URI
     * @param extension The extension value, or {@code null} to remove it
     * @since 5.4.0
     */
    @JsonAnySetter
    public void setExtension(String schema, @Nullable Object extension) {
        String validated = requireAbsoluteUri(schema);
        if (extension == null) {
            extensions.remove(validated);
            removeSchema(validated);
        } else {
            extensions.put(validated, extension);
            addSchema(validated);
        }
    }

    /**
     * Looks up a custom extension by schema URI.
     *
     * @param schema The extension schema URI
     * @return The extension value, if present
     * @since 5.4.0
     */
    @Nullable
    @JsonIgnore
    public Object getExtension(String schema) {
        return extensions.get(schema);
    }

    private static String requireAbsoluteUri(String value) {
        Objects.requireNonNull(value, "schema");
        URI uri = URI.create(value);
        if (!uri.isAbsolute()) {
            throw new IllegalArgumentException("schema must be an absolute URI: " + value);
        }
        return value;
    }
}
