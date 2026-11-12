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
package io.micronaut.security.scim.data.jdbc.repositories;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.data.repository.CrudRepository;
import io.micronaut.security.scim.data.entities.ScimResourceExtensionEntity;
import io.micronaut.security.scim.data.entities.ScimResourceType;

import java.util.List;
import java.util.Optional;

/**
 * JDBC repository for custom SCIM resource extension rows.
 *
 * @since 5.4.0
 */
@Experimental
public interface ScimResourceExtensionJdbcRepository extends CrudRepository<ScimResourceExtensionEntity, Long> {

    /**
     * Finds every custom extension attached to a resource.
     *
     * @param resourceType The owning resource type
     * @param resourceId The owning resource identifier
     * @return The resource extensions
     * @since 5.4.0
     */
    List<ScimResourceExtensionEntity> findAllByResourceTypeAndResourceId(
        ScimResourceType resourceType,
        String resourceId
    );

    /**
     * Finds a particular schema extension attached to a resource.
     *
     * @param resourceType The owning resource type
     * @param resourceId The owning resource identifier
     * @param schemaUri The extension schema URI
     * @return The matching extension, if present
     * @since 5.4.0
     */
    Optional<ScimResourceExtensionEntity> findByResourceTypeAndResourceIdAndSchemaUri(
        ScimResourceType resourceType,
        String resourceId,
        String schemaUri
    );

    /**
     * Deletes every custom extension attached to a resource.
     *
     * @param resourceType The owning resource type
     * @param resourceId The owning resource identifier
     * @return The number of deleted rows
     * @since 5.4.0
     */
    long deleteByResourceTypeAndResourceId(ScimResourceType resourceType, String resourceId);
}
