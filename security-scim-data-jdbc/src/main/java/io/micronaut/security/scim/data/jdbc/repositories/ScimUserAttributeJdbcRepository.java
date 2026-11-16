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
import io.micronaut.security.scim.data.entities.ScimUserAttributeEntity;
import io.micronaut.security.scim.data.entities.ScimUserAttributeKind;

import java.util.List;

/**
 * JDBC repository for SCIM multi-valued User attribute rows.
 *
 * @since 5.4.0
 */
@Experimental
public interface ScimUserAttributeJdbcRepository extends CrudRepository<ScimUserAttributeEntity, Long> {

    /**
     * Finds all multi-valued attributes owned by a User.
     *
     * @param userId The User identifier
     * @return The User attributes
     * @since 5.4.0
     */
    List<ScimUserAttributeEntity> findAllByUserIdOrderByAttributeKindAndPosition(String userId);

    /**
     * Finds one kind of multi-valued attribute in its persisted order.
     *
     * @param userId The User identifier
     * @param attributeKind The attribute kind
     * @return The matching User attributes
     * @since 5.4.0
     */
    List<ScimUserAttributeEntity> findAllByUserIdAndAttributeKindOrderByPosition(
        String userId,
        ScimUserAttributeKind attributeKind
    );

    /**
     * Deletes every multi-valued attribute owned by a User.
     *
     * @param userId The User identifier
     * @return The number of deleted rows
     * @since 5.4.0
     */
    long deleteByUserId(String userId);

    /**
     * Deletes one kind of multi-valued attribute owned by a User.
     *
     * @param userId The User identifier
     * @param attributeKind The attribute kind
     * @return The number of deleted rows
     * @since 5.4.0
     */
    long deleteByUserIdAndAttributeKind(String userId, ScimUserAttributeKind attributeKind);
}
