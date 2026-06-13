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
package io.micronaut.security.authentication;

import io.micronaut.json.JsonMapper;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.json.JSONException;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;

@MicronautTest(startApplication = false)
class ClientAuthenticationTest {
    private static final Authentication AUTH = new ClientAuthentication("sergio",
        Map.of("roles", List.of("ROLE_USER"), "family_name", "del Amo", "given_name", "Sergio"));
    private static final String JSON = """
            {"name":"sergio","attributes":{"family_name":"del Amo","given_name":"Sergio","roles":["ROLE_USER"]}}""";

    @Test
    void serializeAsJson(JsonMapper jsonMapper) throws IOException, JSONException {
        String result = jsonMapper.writeValueAsString(AUTH);
        JSONAssert.assertEquals(JSON, result, true);
    }

    @Test
    void deserializeAsJson(JsonMapper jsonMapper) throws IOException {
        Authentication result = jsonMapper.readValue(JSON, ClientAuthentication.class);
        assertEquals(AUTH, result);
    }

    @Test
    void equalsAndHashCodeTest() {
        ClientAuthentication authentication = new ClientAuthentication("sergio",
            Map.of("roles", List.of("ROLE_USER"), "family_name", "del Amo", "given_name", "Sergio"));
        ClientAuthentication same = new ClientAuthentication("sergio",
            Map.of("roles", List.of("ROLE_USER"), "family_name", "del Amo", "given_name", "Sergio"));

        assertEquals(authentication, same);
        assertEquals(authentication.hashCode(), same.hashCode());
        assertNotEquals(authentication, new ClientAuthentication("aegon",
            Map.of("roles", List.of("ROLE_USER"), "family_name", "del Amo", "given_name", "Sergio")));
        assertNotEquals(authentication, new ClientAuthentication("sergio",
            Map.of("roles", List.of("ROLE_KING"), "family_name", "del Amo", "given_name", "Sergio")));
        assertNotEquals(authentication, null);
        assertNotEquals(authentication, new Object());
    }

    @Test
    void withAttributesReturnsAuthenticationWithDifferentAttributes() {
        Authentication result = AUTH.withAttributes(Map.of("family_name", "Targaryen"));

        assertNotSame(AUTH, result);
        assertEquals(AUTH.getName(), result.getName());
        assertEquals(AUTH.getRoles().stream().toList(), result.getRoles().stream().toList());
        assertEquals(Map.of("family_name", "Targaryen"), result.getAttributes());
        assertEquals(
            Map.of("roles", List.of("ROLE_USER"), "family_name", "del Amo", "given_name", "Sergio"),
            AUTH.getAttributes()
        );
    }

    @Test
    void withAttributesAppendsAttributes() {
        Authentication result = AUTH.withAttributes(Map.of("family_name", "Targaryen", "nickname", "Aegon"), true);

        assertNotSame(AUTH, result);
        assertEquals(AUTH.getName(), result.getName());
        assertEquals(AUTH.getRoles().stream().toList(), result.getRoles().stream().toList());
        assertEquals(
            Map.of("roles", List.of("ROLE_USER"), "family_name", "Targaryen", "given_name", "Sergio", "nickname", "Aegon"),
            result.getAttributes()
        );
        assertEquals(
            Map.of("roles", List.of("ROLE_USER"), "family_name", "del Amo", "given_name", "Sergio"),
            AUTH.getAttributes()
        );
    }

    @Test
    void withRolesReturnsAuthenticationWithDifferentRoles() {
        Authentication result = AUTH.withRoles(List.of("ROLE_ADMIN"));

        assertNotSame(AUTH, result);
        assertEquals(AUTH.getName(), result.getName());
        assertEquals(List.of("ROLE_ADMIN"), result.getRoles().stream().toList());
        assertEquals(AUTH.getAttributes(), result.getAttributes());
        assertEquals(List.of("ROLE_USER"), AUTH.getRoles().stream().toList());
    }

    @Test
    void withRolesAppendsRoles() {
        Authentication result = AUTH.withRoles(List.of("ROLE_ADMIN", "ROLE_KING"), true);

        assertNotSame(AUTH, result);
        assertEquals(AUTH.getName(), result.getName());
        assertEquals(List.of("ROLE_USER", "ROLE_ADMIN", "ROLE_KING"), result.getRoles().stream().toList());
        assertEquals(AUTH.getAttributes(), result.getAttributes());
        assertEquals(List.of("ROLE_USER"), AUTH.getRoles().stream().toList());
    }

    @Test
    void withUsernameReturnsAuthenticationWithDifferentUsername() {
        Authentication result = AUTH.withUsername("aegon");

        assertNotSame(AUTH, result);
        assertEquals("aegon", result.getName());
        assertEquals(AUTH.getRoles().stream().toList(), result.getRoles().stream().toList());
        assertEquals(AUTH.getAttributes(), result.getAttributes());
        assertEquals("sergio", AUTH.getName());
    }
}
