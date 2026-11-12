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

import io.micronaut.security.scim.data.entities.ScimEnterpriseUserEntity;
import io.micronaut.security.scim.data.entities.ScimGroupEntity;
import io.micronaut.security.scim.data.entities.ScimGroupMemberEntity;
import io.micronaut.security.scim.data.entities.ScimResourceExtensionEntity;
import io.micronaut.security.scim.data.entities.ScimResourceType;
import io.micronaut.security.scim.data.entities.ScimUserAddressEntity;
import io.micronaut.security.scim.data.entities.ScimUserAttributeEntity;
import io.micronaut.security.scim.data.entities.ScimUserAttributeKind;
import io.micronaut.security.scim.data.entities.ScimUserEntity;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
class ScimJdbcRepositoriesTest {

    @Inject
    ScimUserJdbcRepository userRepository;

    @Inject
    ScimGroupJdbcRepository groupRepository;

    @Inject
    ScimGroupMemberJdbcRepository groupMemberRepository;

    @Inject
    ScimUserAddressJdbcRepository userAddressRepository;

    @Inject
    ScimUserAttributeJdbcRepository userAttributeRepository;

    @Inject
    ScimEnterpriseUserJdbcRepository enterpriseUserRepository;

    @Inject
    ScimResourceExtensionJdbcRepository resourceExtensionRepository;

    @Test
    void userRepositorySupportsScimLookups() {
        userRepository.save(user("user-1", "external-user", "bjensen"));

        assertEquals("user-1", userRepository.findByUserNameIgnoreCase("BJENSEN").orElseThrow().id());
        assertTrue(userRepository.existsByUserNameIgnoreCase("BjEnSeN"));
        assertEquals(1, userRepository.findAllByExternalId("external-user").size());
    }

    @Test
    void groupRepositorySupportsScimLookups() {
        groupRepository.save(new ScimGroupEntity(
            "group-1", "external-group", "Employees", null, null, null));

        assertEquals(1, groupRepository.findAllByExternalId("external-group").size());
        assertEquals("group-1", groupRepository.findAllByDisplayNameIgnoreCase("EMPLOYEES").getFirst().id());
    }

    @Test
    void groupMemberRepositorySupportsAggregateOperations() {
        groupMemberRepository.save(new ScimGroupMemberEntity(
            null, "group-2", "user-2", ScimResourceType.USER, null, null));
        groupMemberRepository.save(new ScimGroupMemberEntity(
            null, "group-2", "group-3", ScimResourceType.GROUP, null, null));

        assertEquals(2, groupMemberRepository.findAllByGroupIdOrderById("group-2").size());
        assertEquals(1,
            groupMemberRepository.findAllByMemberIdAndMemberType("user-2", ScimResourceType.USER).size());
        assertEquals(1,
            groupMemberRepository.deleteByGroupIdAndMemberIdAndMemberType(
                "group-2", "user-2", ScimResourceType.USER));
        assertEquals(1, groupMemberRepository.deleteByGroupId("group-2"));
    }

    @Test
    void userAddressRepositorySupportsAggregateOperations() {
        userAddressRepository.save(new ScimUserAddressEntity(
            null, "user-3", null, "100 Universal City Plaza", "Hollywood", "CA", "91608", "US",
            "work", true, 0));

        assertEquals(1, userAddressRepository.findAllByUserIdOrderByPosition("user-3").size());
        assertEquals(1, userAddressRepository.deleteByUserId("user-3"));
    }

    @Test
    void userAttributeRepositorySupportsAggregateOperations() {
        userAttributeRepository.save(new ScimUserAttributeEntity(
            null, "user-4", ScimUserAttributeKind.EMAIL, "bjensen@example.com", "work", true,
            null, null, 0));
        userAttributeRepository.save(new ScimUserAttributeEntity(
            null, "user-4", ScimUserAttributeKind.ROLE, "employee", null, null, null, null, 0));

        assertEquals(2,
            userAttributeRepository.findAllByUserIdOrderByAttributeKindAndPosition("user-4").size());
        assertEquals(1,
            userAttributeRepository.findAllByUserIdAndAttributeKindOrderByPosition(
                "user-4", ScimUserAttributeKind.EMAIL).size());
        assertEquals(1,
            userAttributeRepository.deleteByUserIdAndAttributeKind("user-4", ScimUserAttributeKind.EMAIL));
        assertEquals(1, userAttributeRepository.deleteByUserId("user-4"));
    }

    @Test
    void enterpriseUserRepositorySupportsCrudOperations() {
        enterpriseUserRepository.save(new ScimEnterpriseUserEntity(
            "user-5", "701984", null, null, null, "Sales", null, null, null));

        assertEquals("701984", enterpriseUserRepository.findById("user-5").orElseThrow().employeeNumber());
        enterpriseUserRepository.deleteById("user-5");
        assertFalse(enterpriseUserRepository.existsById("user-5"));
    }

    @Test
    void resourceExtensionRepositorySupportsAggregateOperations() {
        String schemaUri = "urn:example:params:scim:schemas:extension:custom:2.0:User";
        resourceExtensionRepository.save(new ScimResourceExtensionEntity(
            null, ScimResourceType.USER, "user-6", schemaUri, "{\"departmentNumber\":42}"));

        assertEquals(1,
            resourceExtensionRepository.findAllByResourceTypeAndResourceId(
                ScimResourceType.USER, "user-6").size());
        assertTrue(resourceExtensionRepository.findByResourceTypeAndResourceIdAndSchemaUri(
            ScimResourceType.USER, "user-6", schemaUri).isPresent());
        assertEquals(1,
            resourceExtensionRepository.deleteByResourceTypeAndResourceId(
                ScimResourceType.USER, "user-6"));
    }

    private static ScimUserEntity user(String id, String externalId, String userName) {
        return new ScimUserEntity(
            id,
            externalId,
            userName,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null
        );
    }
}
