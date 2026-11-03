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
package io.micronaut.security.scim.core.docs;

import io.micronaut.security.scim.core.EnterpriseUser;
import io.micronaut.security.scim.core.MultiValuedAttribute;
import io.micronaut.security.scim.core.Name;
import io.micronaut.security.scim.core.SchemaUris;
import io.micronaut.security.scim.core.User;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScimCoreExample {

    @Test
    void createsUser() {
        //tag::user[]
        User user = new User();
        user.setUserName("bjensen@example.com");
        user.setName(new Name(
            "Barbara Jensen", "Jensen", "Barbara", null, null, null));
        user.setEmails(List.of(new MultiValuedAttribute(
            "bjensen@example.com", "work", true, null, null)));
        user.setActive(true);
        //end::user[]

        assertEquals(List.of(SchemaUris.USER), user.getSchemas());
        assertEquals("Jensen", user.getName().familyName());
    }

    @Test
    void addsEnterpriseUserExtension() {
        User user = new User();

        //tag::enterpriseUser[]
        user.setEnterpriseUser(new EnterpriseUser(
            "701984", "4130", "Acme", "Platform", "Engineering", null));
        //end::enterpriseUser[]

        assertTrue(user.getSchemas().contains(SchemaUris.ENTERPRISE_USER));
    }

    @Test
    void addsCustomExtension() {
        User user = new User();

        //tag::customExtension[]
        String extensionSchema =
            "urn:example:params:scim:schemas:extension:custom:2.0:User";
        user.setExtension(extensionSchema, Map.of("badgeNumber", "A-123"));
        //end::customExtension[]

        assertTrue(user.getSchemas().contains(extensionSchema));
        assertEquals(Map.of("badgeNumber", "A-123"), user.getExtension(extensionSchema));
    }
}
