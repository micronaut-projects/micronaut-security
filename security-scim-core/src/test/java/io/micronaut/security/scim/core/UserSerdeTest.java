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
package io.micronaut.security.scim.core;

import io.micronaut.json.JsonMapper;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
class UserSerdeTest {
    private static final String CUSTOM_EXTENSION = "urn:example:params:scim:schemas:extension:custom:2.0:User";

    @Test
    void deserializesEnterpriseUserRepresentation(JsonMapper jsonMapper) throws IOException {
        String json = """
            {
              "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User",
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
              ],
              "id": "2819c223-7f76-453a-919d-413861904646",
              "externalId": "701984",
              "userName": "bjensen@example.com",
              "name": {
                "formatted": "Ms. Barbara J Jensen, III",
                "familyName": "Jensen",
                "givenName": "Barbara",
                "middleName": "Jane",
                "honorificPrefix": "Ms.",
                "honorificSuffix": "III"
              },
              "displayName": "Babs Jensen",
              "active": true,
              "emails": [
                {"value": "bjensen@example.com", "type": "work", "primary": true}
              ],
              "groups": [
                {
                  "value": "e9e30dba-f08f-4109-8486-d5c6a331660a",
                  "$ref": "../Groups/e9e30dba-f08f-4109-8486-d5c6a331660a",
                  "display": "Tour Guides",
                  "type": "direct"
                }
              ],
              "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "employeeNumber": "701984",
                "costCenter": "4130",
                "organization": "Universal Studios",
                "division": "Theme Park",
                "department": "Tour Operations",
                "manager": {
                  "value": "26118915-6090-4610-87e4-49d8ca9f808d",
                  "$ref": "../Users/26118915-6090-4610-87e4-49d8ca9f808d",
                  "displayName": "John Smith"
                }
              },
              "meta": {
                "resourceType": "User",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": "W/\\\"3694e05e9dff591\\\"",
                "location": "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646"
              }
            }
            """;

        User user = jsonMapper.readValue(json, User.class);

        assertEquals("bjensen@example.com", user.getUserName());
        assertEquals("Jensen", user.getName().familyName());
        assertEquals("bjensen@example.com", user.getEmails().get(0).value());
        assertEquals("../Groups/e9e30dba-f08f-4109-8486-d5c6a331660a", user.getGroups().get(0).ref());
        assertTrue(user.getSchemas().contains(SchemaUris.ENTERPRISE_USER));
        assertEquals("701984", user.getEnterpriseUser().employeeNumber());
        assertEquals("John Smith", user.getEnterpriseUser().manager().displayName());
        assertEquals("User", user.getMeta().resourceType());

        String encoded = jsonMapper.writeValueAsString(user);
        assertTrue(encoded.contains('"' + SchemaUris.ENTERPRISE_USER + '"'));
        assertFalse(encoded.contains("\"enterpriseUser\""));
    }

    @Test
    void passwordIsWriteOnly(JsonMapper jsonMapper) throws IOException {
        User user = jsonMapper.readValue("""
            {
              "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
              "userName": "bjensen@example.com",
              "password": "correct horse battery staple"
            }
            """, User.class);

        assertEquals("correct horse battery staple", user.getPassword());
        assertFalse(jsonMapper.writeValueAsString(user).contains("password"));
    }

    @Test
    void serializesAndDeserializesCustomSchemaExtensions(JsonMapper jsonMapper) throws IOException {
        User user = new User();
        user.setUserName("bjensen@example.com");
        user.setExtension(CUSTOM_EXTENSION, Map.of("badgeNumber", "A-123"));

        String json = jsonMapper.writeValueAsString(user);
        User decoded = jsonMapper.readValue(json, User.class);

        assertTrue(json.contains('"' + CUSTOM_EXTENSION + '"'));
        assertTrue(decoded.getSchemas().contains(CUSTOM_EXTENSION));
        Map<?, ?> extension = assertInstanceOf(Map.class, decoded.getExtension(CUSTOM_EXTENSION));
        assertEquals("A-123", extension.get("badgeNumber"));
    }

    @Test
    void rejectsInvalidSchemas() {
        User user = new User();

        assertThrows(IllegalArgumentException.class, () -> user.setSchemas(List.of()));
        assertThrows(IllegalArgumentException.class, () -> user.setSchemas(List.of(SchemaUris.GROUP)));
        assertThrows(IllegalArgumentException.class,
            () -> user.setSchemas(List.of(SchemaUris.USER, SchemaUris.USER)));
        assertThrows(IllegalArgumentException.class, () -> user.addSchema("relative-schema"));
        assertFalse(user.removeSchema(SchemaUris.USER));
    }
}
