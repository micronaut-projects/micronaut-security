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
package io.micronaut.security.scim.data.jdbc.http.service;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.security.scim.core.Group;
import io.micronaut.security.scim.core.ResourceReference;
import io.micronaut.security.scim.core.User;
import io.micronaut.security.scim.server.exception.ScimException;
import io.micronaut.security.scim.server.model.ScimAttributeSelection;
import io.micronaut.security.scim.server.model.ScimRequestContext;
import io.micronaut.security.scim.server.model.ScimResourceResponse;
import io.micronaut.security.scim.server.protocol.ScimMessageSchemas;
import io.micronaut.security.scim.server.protocol.ScimErrorType;
import io.micronaut.security.scim.server.protocol.ScimPatchOperation;
import io.micronaut.security.scim.server.protocol.ScimPatchOperationType;
import io.micronaut.security.scim.server.protocol.ScimPatchRequest;
import io.micronaut.security.scim.server.service.ScimGroupService;
import io.micronaut.security.scim.server.service.ScimUserService;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false, transactional = false)
class DefaultJdbcScimGroupServiceTest {

    @Inject
    ScimUserService userService;

    @Inject
    ScimGroupService groupService;

    @Test
    void persistsGroupMembershipAndDerivesTheUsersGroupsAttribute() {
        assertInstanceOf(DefaultJdbcScimGroupService.class, groupService);
        User user = new User();
        user.setUserName("group-member-" + System.nanoTime() + "@example.com");
        ScimResourceResponse<User> createdUser = userService.create(user, context("/scim/v2/Users", null));

        Group group = new Group();
        group.setDisplayName("Tour Guides " + System.nanoTime());
        group.setMembers(List.of(new ResourceReference(
            createdUser.resource().getId(), createdUser.location().toString(), "Babs Jensen", "User")));

        ScimResourceResponse<Group> created = groupService.create(group, context("/scim/v2/Groups", null));

        Group found = groupService.get(
            created.resource().getId(), context("/scim/v2/Groups/" + created.resource().getId(), null))
            .orElseThrow().resource();
        assertEquals(createdUser.resource().getId(), found.getMembers().getFirst().value());
        assertEquals("User", found.getMembers().getFirst().type());

        User foundUser = userService.get(
            createdUser.resource().getId(), context("/scim/v2/Users/" + createdUser.resource().getId(), null))
            .orElseThrow().resource();
        assertEquals(created.resource().getId(), foundUser.getGroups().getFirst().value());
        assertEquals("direct", foundUser.getGroups().getFirst().type());

        ScimPatchRequest replaceDisplay = new ScimPatchRequest(
            List.of(ScimMessageSchemas.PATCH_OPERATION),
            List.of(new ScimPatchOperation(
                ScimPatchOperationType.REPLACE,
                "members[value eq \"" + createdUser.resource().getId() + "\"].display",
                "Updated display"
            ))
        );
        Group patched = groupService.patch(
            found.getId(), replaceDisplay, context("/scim/v2/Groups/" + found.getId(), null))
            .orElseThrow().resource();
        assertEquals("Updated display", patched.getMembers().getFirst().display());

        ScimPatchRequest removeMember = new ScimPatchRequest(
            List.of(ScimMessageSchemas.PATCH_OPERATION),
            List.of(new ScimPatchOperation(
                ScimPatchOperationType.REMOVE,
                "members[value eq \"" + createdUser.resource().getId() + "\"]",
                null
            ))
        );
        Group withoutMember = groupService.patch(
            found.getId(), removeMember, context("/scim/v2/Groups/" + found.getId(), null))
            .orElseThrow().resource();
        assertTrue(withoutMember.getMembers().isEmpty());

        groupService.delete(found.getId(), context("/scim/v2/Groups/" + found.getId(), null));
        assertFalse(groupService.get(found.getId(), context("/scim/v2/Groups/" + found.getId(), null)).isPresent());
        userService.delete(foundUser.getId(), context("/scim/v2/Users/" + foundUser.getId(), null));
    }

    @Test
    void rejectsDuplicateGroupDisplayNamesIgnoringCase() {
        String displayName = "Duplicate Group " + System.nanoTime();
        Group first = new Group();
        first.setDisplayName(displayName);
        ScimResourceResponse<Group> created = groupService.create(first, context("/scim/v2/Groups", null));

        Group sameGroup = new Group();
        sameGroup.setDisplayName(displayName.toUpperCase());
        Group replaced = groupService.replace(created.resource().getId(), sameGroup,
            context("/scim/v2/Groups/" + created.resource().getId(), null)).orElseThrow().resource();
        assertEquals(displayName.toUpperCase(), replaced.getDisplayName());

        Group duplicate = new Group();
        duplicate.setDisplayName(displayName.toLowerCase());
        ScimException exception = assertThrows(ScimException.class,
            () -> groupService.create(duplicate, context("/scim/v2/Groups", null)));
        assertEquals(HttpStatus.CONFLICT, exception.getStatus());
        assertEquals(ScimErrorType.UNIQUENESS, exception.getScimType());
    }

    private static ScimRequestContext context(String uri, String ifMatch) {
        return new ScimRequestContext(HttpRequest.GET(uri), ScimAttributeSelection.ALL, ifMatch);
    }
}
