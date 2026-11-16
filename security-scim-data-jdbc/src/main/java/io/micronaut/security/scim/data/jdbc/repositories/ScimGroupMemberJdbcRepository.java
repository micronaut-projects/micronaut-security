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
import io.micronaut.security.scim.data.entities.ScimGroupMemberEntity;
import io.micronaut.security.scim.data.entities.ScimResourceType;

import java.util.List;

/**
 * JDBC repository for SCIM Group membership rows.
 *
 * @since 5.4.0
 */
@Experimental
public interface ScimGroupMemberJdbcRepository extends CrudRepository<ScimGroupMemberEntity, Long> {

    /**
     * Finds the members of a Group in stable row order.
     *
     * @param groupId The Group identifier
     * @return The Group members
     * @since 5.4.0
     */
    List<ScimGroupMemberEntity> findAllByGroupIdOrderById(String groupId);

    /**
     * Finds every Group that directly contains the referenced resource.
     *
     * @param memberId The referenced resource identifier
     * @param memberType The referenced resource type
     * @return The matching memberships
     * @since 5.4.0
     */
    List<ScimGroupMemberEntity> findAllByMemberIdAndMemberType(String memberId, ScimResourceType memberType);

    /**
     * Deletes every member row owned by a Group.
     *
     * @param groupId The Group identifier
     * @return The number of deleted rows
     * @since 5.4.0
     */
    long deleteByGroupId(String groupId);

    /**
     * Deletes memberships that reference a resource.
     *
     * @param memberId The referenced resource identifier
     * @param memberType The referenced resource type
     * @return The number of deleted rows
     * @since 5.4.0
     */
    long deleteByMemberIdAndMemberType(String memberId, ScimResourceType memberType);

    /**
     * Deletes one direct membership.
     *
     * @param groupId The Group identifier
     * @param memberId The referenced resource identifier
     * @param memberType The referenced resource type
     * @return The number of deleted rows
     * @since 5.4.0
     */
    long deleteByGroupIdAndMemberIdAndMemberType(
        String groupId,
        String memberId,
        ScimResourceType memberType
    );
}
