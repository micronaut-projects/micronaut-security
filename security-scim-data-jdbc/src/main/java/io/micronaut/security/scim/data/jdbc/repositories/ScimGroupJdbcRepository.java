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
import io.micronaut.data.repository.PageableRepository;
import io.micronaut.security.scim.data.entities.ScimGroupEntity;

import java.util.List;

/**
 * JDBC repository for SCIM Group resources.
 *
 * @since 5.4.0
 */
@Experimental
public interface ScimGroupJdbcRepository extends PageableRepository<ScimGroupEntity, String> {

    /**
     * Finds Groups with the supplied client-assigned identifier.
     *
     * @param externalId The client-assigned identifier
     * @return The matching Groups
     * @since 5.4.0
     */
    List<ScimGroupEntity> findAllByExternalId(String externalId);

    /**
     * Finds Groups with the supplied case-insensitive display name.
     *
     * @param displayName The Group display name
     * @return The matching Groups
     * @since 5.4.0
     */
    List<ScimGroupEntity> findAllByDisplayNameIgnoreCase(String displayName);
}
