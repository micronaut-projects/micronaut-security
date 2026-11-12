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
import io.micronaut.security.scim.data.entities.ScimUserAddressEntity;

import java.util.List;

/**
 * JDBC repository for SCIM User address rows.
 *
 * @since 5.4.0
 */
@Experimental
public interface ScimUserAddressJdbcRepository extends CrudRepository<ScimUserAddressEntity, Long> {

    /**
     * Finds a User's addresses in their persisted order.
     *
     * @param userId The User identifier
     * @return The User addresses
     * @since 5.4.0
     */
    List<ScimUserAddressEntity> findAllByUserIdOrderByPosition(String userId);

    /**
     * Deletes every address owned by a User.
     *
     * @param userId The User identifier
     * @return The number of deleted rows
     * @since 5.4.0
     */
    long deleteByUserId(String userId);
}
