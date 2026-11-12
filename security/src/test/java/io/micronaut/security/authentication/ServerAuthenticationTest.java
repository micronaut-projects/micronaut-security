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
class ServerAuthenticationTest {

    @Test
    void serializeAsJson(JsonMapper jsonMapper) throws IOException, JSONException {
        String json = jsonMapper.writeValueAsString(new ServerAuthentication("sergio", List.of("ROLE_USER"),
            Map.of("family_name", "del Amo", "given_name", "Sergio")));
        String expected = """
            {"name":"sergio","attributes":{"family_name":"del Amo","given_name":"Sergio","roles":["ROLE_USER"]}}""";
        JSONAssert.assertEquals(expected, json, true);
    }

    @Test
    void equalsAndHashCodeTest() {
        ServerAuthentication authentication = new ServerAuthentication("sergio",
            List.of("ROLE_USER"),
            Map.of("family_name", "del Amo", "given_name", "Sergio"));
        ServerAuthentication same = new ServerAuthentication("sergio",
            List.of("ROLE_USER"),
            Map.of("family_name", "del Amo", "given_name", "Sergio"));

        assertEquals(authentication, same);
        assertEquals(authentication.hashCode(), same.hashCode());
        assertNotEquals(authentication, new ServerAuthentication("aegon",
            List.of("ROLE_USER"),
            Map.of("family_name", "del Amo", "given_name", "Sergio")));
        assertNotEquals(authentication, new ServerAuthentication("sergio",
            List.of("ROLE_ADMIN"),
            Map.of("family_name", "del Amo", "given_name", "Sergio")));
        assertNotEquals(authentication, new ServerAuthentication("sergio",
            List.of("ROLE_USER"),
            Map.of("family_name", "Targaryen", "given_name", "Sergio")));
        assertNotEquals(authentication, null);
        assertNotEquals(authentication, new Object());
    }

    @Test
    void withAttributesReturnsAuthenticationWithDifferentAttributes() {
        Authentication authentication = new ServerAuthentication("sergio",
            List.of("ROLE_USER"),
            Map.of("family_name", "del Amo"));

        Authentication result = authentication.withAttributes(Map.of("family_name", "Targaryen"));

        assertNotSame(authentication, result);
        assertEquals(authentication.getName(), result.getName());
        assertEquals(authentication.getRoles().stream().toList(), result.getRoles().stream().toList());
        assertEquals(Map.of("family_name", "Targaryen"), result.getAttributes());
        assertEquals(Map.of("family_name", "del Amo"), authentication.getAttributes());
    }

    @Test
    void withAttributesAppendsAttributes() {
        Authentication authentication = new ServerAuthentication("sergio",
            List.of("ROLE_USER"),
            Map.of("family_name", "del Amo", "given_name", "Sergio"));

        Authentication result = authentication.withAttributes(
            Map.of("family_name", "Targaryen", "nickname", "Aegon"),
            true
        );

        assertNotSame(authentication, result);
        assertEquals(authentication.getName(), result.getName());
        assertEquals(authentication.getRoles().stream().toList(), result.getRoles().stream().toList());
        assertEquals(
            Map.of("family_name", "Targaryen", "given_name", "Sergio", "nickname", "Aegon"),
            result.getAttributes()
        );
        assertEquals(Map.of("family_name", "del Amo", "given_name", "Sergio"), authentication.getAttributes());
    }

    @Test
    void withAttributesDoesNotAppendWhenAppendIsFalse() {
        Authentication authentication = new ServerAuthentication("sergio",
            List.of("ROLE_USER"),
            Map.of("family_name", "del Amo", "given_name", "Sergio"));

        Authentication result = authentication.withAttributes(Map.of("family_name", "Targaryen"), false);

        assertEquals(Map.of("family_name", "Targaryen"), result.getAttributes());
    }

    @Test
    void withRolesReturnsAuthenticationWithDifferentRoles() {
        Authentication authentication = new ServerAuthentication("sergio",
            List.of("ROLE_USER"),
            Map.of("family_name", "del Amo"));

        Authentication result = authentication.withRoles(List.of("ROLE_ADMIN"));

        assertNotSame(authentication, result);
        assertEquals(authentication.getName(), result.getName());
        assertEquals(List.of("ROLE_ADMIN"), result.getRoles().stream().toList());
        assertEquals(authentication.getAttributes(), result.getAttributes());
        assertEquals(List.of("ROLE_USER"), authentication.getRoles().stream().toList());
    }

    @Test
    void withRolesAppendsRoles() {
        Authentication authentication = new ServerAuthentication("sergio",
            List.of("ROLE_USER"),
            Map.of("family_name", "del Amo"));

        Authentication result = authentication.withRoles(List.of("ROLE_ADMIN", "ROLE_KING"), true);

        assertNotSame(authentication, result);
        assertEquals(authentication.getName(), result.getName());
        assertEquals(List.of("ROLE_USER", "ROLE_ADMIN", "ROLE_KING"), result.getRoles().stream().toList());
        assertEquals(authentication.getAttributes(), result.getAttributes());
        assertEquals(List.of("ROLE_USER"), authentication.getRoles().stream().toList());
    }

    @Test
    void withRolesDoesNotAppendWhenAppendIsFalse() {
        Authentication authentication = new ServerAuthentication("sergio",
            List.of("ROLE_USER"),
            Map.of("family_name", "del Amo"));

        Authentication result = authentication.withRoles(List.of("ROLE_ADMIN"), false);

        assertEquals(List.of("ROLE_ADMIN"), result.getRoles().stream().toList());
    }

    @Test
    void withUsernameReturnsAuthenticationWithDifferentUsername() {
        Authentication authentication = new ServerAuthentication("sergio",
            List.of("ROLE_USER"),
            Map.of("family_name", "del Amo"));

        Authentication result = authentication.withUsername("aegon");

        assertNotSame(authentication, result);
        assertEquals("aegon", result.getName());
        assertEquals(authentication.getRoles().stream().toList(), result.getRoles().stream().toList());
        assertEquals(authentication.getAttributes(), result.getAttributes());
        assertEquals("sergio", authentication.getName());
    }
}
