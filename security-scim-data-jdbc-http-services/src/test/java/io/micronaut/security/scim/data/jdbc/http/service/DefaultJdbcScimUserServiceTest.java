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
import io.micronaut.security.scim.core.Address;
import io.micronaut.security.scim.core.EnterpriseUser;
import io.micronaut.security.scim.core.Manager;
import io.micronaut.security.scim.core.MultiValuedAttribute;
import io.micronaut.security.scim.core.Name;
import io.micronaut.security.scim.core.SchemaUris;
import io.micronaut.security.scim.core.User;
import io.micronaut.security.scim.server.filter.ScimFilterParser;
import io.micronaut.security.scim.server.model.ScimAttributeSelection;
import io.micronaut.security.scim.server.model.ScimQuery;
import io.micronaut.security.scim.server.model.ScimRequestContext;
import io.micronaut.security.scim.server.model.ScimResourceResponse;
import io.micronaut.security.scim.server.protocol.ScimMessageSchemas;
import io.micronaut.security.scim.server.protocol.ScimPatchOperation;
import io.micronaut.security.scim.server.protocol.ScimPatchOperationType;
import io.micronaut.security.scim.server.protocol.ScimPatchRequest;
import io.micronaut.security.scim.server.protocol.ScimSortOrder;
import io.micronaut.security.scim.server.service.ScimUserService;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false, transactional = false)
class DefaultJdbcScimUserServiceTest {

    @Inject
    ScimUserService userService;

    @Inject
    ScimFilterParser filterParser;

    @Test
    void persistsSearchesPatchesAndDeletesACompleteUser() {
        assertInstanceOf(DefaultJdbcScimUserService.class, userService);
        String userName = "bjensen-" + System.nanoTime() + "@example.com";
        User user = new User();
        user.setUserName(userName);
        user.setExternalId("external-" + System.nanoTime());
        user.setName(new Name("Ms. Barbara J Jensen III", "Jensen", "Barbara", "Jane", "Ms.", "III"));
        user.setDisplayName("Babs Jensen");
        user.setActive(true);
        user.setEmails(List.of(new MultiValuedAttribute(
            "bjensen@example.com", "work", true, null, null)));
        user.setAddresses(List.of(new Address(
            "100 Universal City Plaza, Hollywood, CA 91608 USA",
            "100 Universal City Plaza", "Hollywood", "CA", "91608", "US", "work", true)));
        user.setEnterpriseUser(new EnterpriseUser(
            "701984", "4130", "Universal Studios", "Theme Park", "Tour Operations",
            new Manager("26118915", "/scim/v2/Users/26118915", "John Smith")));
        String extensionSchema = "urn:example:params:scim:schemas:extension:custom:2.0:User";
        user.setExtension(extensionSchema, Map.of("badgeNumber", 42));

        ScimResourceResponse<User> created = userService.create(user, context("/scim/v2/Users", null));

        assertNotNull(created.resource().getId());
        assertTrue(created.location().toString().endsWith("/scim/v2/Users/" + created.resource().getId()));
        assertEquals("701984", created.resource().getEnterpriseUser().employeeNumber());
        assertEquals(42, ((Number) ((Map<?, ?>) created.resource().getExtension(extensionSchema)).get("badgeNumber")).intValue());
        assertEquals("bjensen@example.com", created.resource().getEmails().getFirst().value());

        ScimQuery query = new ScimQuery(
            ScimAttributeSelection.ALL,
            filterParser.parse("emails[type eq \"work\" and value co \"@example.com\"]"),
            "emails[type eq \"work\" and value co \"@example.com\"]",
            "userName",
            ScimSortOrder.ASCENDING,
            1,
            10
        );
        assertEquals(List.of(created.resource().getId()), userService.search(query, context("/scim/v2/Users", null))
            .resources().stream().map(User::getId).toList());

        ScimPatchRequest patch = new ScimPatchRequest(
            List.of(ScimMessageSchemas.PATCH_OPERATION),
            List.of(new ScimPatchOperation(ScimPatchOperationType.REPLACE, "displayName", "Barbara Jensen"))
        );
        User patched = userService.patch(
            created.resource().getId(),
            patch,
            context("/scim/v2/Users/" + created.resource().getId(), created.version())
        ).orElseThrow().resource();
        assertEquals("Barbara Jensen", patched.getDisplayName());
        assertEquals(List.of(SchemaUris.USER, SchemaUris.ENTERPRISE_USER, extensionSchema), patched.getSchemas());

        userService.delete(patched.getId(), context("/scim/v2/Users/" + patched.getId(), null));
        assertFalse(userService.get(patched.getId(), context("/scim/v2/Users/" + patched.getId(), null)).isPresent());
    }

    @Test
    void supportsMicrosoftFilteredAndFlattenedPatchPaths() {
        User user = new User();
        user.setUserName("filtered-patch-" + System.nanoTime() + "@example.com");
        ScimResourceResponse<User> created = userService.create(user, context("/scim/v2/Users", null));
        String id = created.resource().getId();

        ScimPatchRequest add = new ScimPatchRequest(
            List.of(ScimMessageSchemas.PATCH_OPERATION),
            List.of(
                new ScimPatchOperation(ScimPatchOperationType.ADD,
                    "emails[type eq \"work\"].value", "jaylen@example.com"),
                new ScimPatchOperation(ScimPatchOperationType.ADD,
                    "emails[type eq \"work\"].primary", true),
                new ScimPatchOperation(ScimPatchOperationType.ADD,
                    "roles[primary eq \"True\"].display", "Initial role"),
                new ScimPatchOperation(ScimPatchOperationType.ADD, null, Map.ofEntries(
                    Map.entry("displayName", "Initial display name"),
                    Map.entry("name.givenName", "Jovan"),
                    Map.entry(SchemaUris.ENTERPRISE_USER + ":employeeNumber", "701984")
                ))
            )
        );

        User added = userService.patch(id, add, context("/scim/v2/Users/" + id, null))
            .orElseThrow().resource();
        assertEquals("jaylen@example.com", added.getEmails().getFirst().value());
        assertEquals("work", added.getEmails().getFirst().type());
        assertEquals(true, added.getEmails().getFirst().primary());
        assertEquals("Initial role", added.getRoles().getFirst().display());
        assertEquals(true, added.getRoles().getFirst().primary());
        assertEquals("Initial display name", added.getDisplayName());
        assertEquals("Jovan", added.getName().givenName());
        assertEquals("701984", added.getEnterpriseUser().employeeNumber());

        ScimPatchRequest replace = new ScimPatchRequest(
            List.of(ScimMessageSchemas.PATCH_OPERATION),
            List.of(
                new ScimPatchOperation(ScimPatchOperationType.REPLACE,
                    "emails[type eq \"work\"].value", "tracey@example.com"),
                new ScimPatchOperation(ScimPatchOperationType.REPLACE, null, Map.of(
                    "name.givenName", "Linda",
                    SchemaUris.ENTERPRISE_USER + ":employeeNumber", "90210"
                ))
            )
        );

        User replaced = userService.patch(id, replace, context("/scim/v2/Users/" + id, null))
            .orElseThrow().resource();
        assertEquals("tracey@example.com", replaced.getEmails().getFirst().value());
        assertEquals("Linda", replaced.getName().givenName());
        assertEquals("90210", replaced.getEnterpriseUser().employeeNumber());
    }

    @Test
    void normalizesMicrosoftScalarManagerPatchValues() {
        User user = new User();
        user.setUserName("manager-patch-" + System.nanoTime() + "@example.com");
        user.setEnterpriseUser(new EnterpriseUser(
            "701984", null, null, null, null, new Manager("old-manager", null, null)));
        ScimResourceResponse<User> created = userService.create(user, context("/scim/v2/Users", null));
        String id = created.resource().getId();
        String managerPath = SchemaUris.ENTERPRISE_USER + ":manager";

        ScimPatchRequest addManager = new ScimPatchRequest(
            List.of(ScimMessageSchemas.PATCH_OPERATION),
            List.of(new ScimPatchOperation(ScimPatchOperationType.ADD, managerPath, "new-manager"))
        );
        User withManager = userService.patch(id, addManager, context("/scim/v2/Users/" + id, null))
            .orElseThrow().resource();
        assertEquals("new-manager", withManager.getEnterpriseUser().manager().value());
        assertEquals("701984", withManager.getEnterpriseUser().employeeNumber());

        ScimPatchRequest removeManager = new ScimPatchRequest(
            List.of(ScimMessageSchemas.PATCH_OPERATION),
            List.of(new ScimPatchOperation(ScimPatchOperationType.REPLACE, managerPath, ""))
        );
        User withoutManager = userService.patch(id, removeManager, context("/scim/v2/Users/" + id, null))
            .orElseThrow().resource();
        assertNull(withoutManager.getEnterpriseUser().manager());
        assertEquals("701984", withoutManager.getEnterpriseUser().employeeNumber());
    }

    private static ScimRequestContext context(String uri, String ifMatch) {
        return new ScimRequestContext(HttpRequest.GET(uri), ScimAttributeSelection.ALL, ifMatch);
    }
}
