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
import io.micronaut.security.scim.data.entities.ScimUserEntity;

import java.util.List;
import java.util.Optional;

/**
 * JDBC repository for SCIM User resources.
 *
 * @since 5.4.0
 */
@Experimental
public interface ScimUserJdbcRepository extends PageableRepository<ScimUserEntity, String> {

    /**
     * Finds a User by its case-insensitive SCIM user name.
     *
     * @param userName The User's user name
     * @return The matching User, if present
     * @since 5.4.0
     */
    Optional<ScimUserEntity> findByUserNameIgnoreCase(String userName);

    /**
     * Finds Users with the supplied client-assigned identifier.
     *
     * @param externalId The client-assigned identifier
     * @return The matching Users
     * @since 5.4.0
     */
    List<ScimUserEntity> findAllByExternalId(String externalId);

    /**
     * Tests whether a case-insensitive SCIM user name is already in use.
     *
     * @param userName The User's user name
     * @return {@code true} when a matching User exists
     * @since 5.4.0
     */
    boolean existsByUserNameIgnoreCase(String userName);
}
