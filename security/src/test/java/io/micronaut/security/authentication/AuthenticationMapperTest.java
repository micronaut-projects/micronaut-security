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

import io.micronaut.context.ApplicationContext;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class AuthenticationMapperTest {

    @Test
    void testAuthenticationMapper() throws IOException {
        try (ApplicationContext applicationContext = ApplicationContext.run()) {
            AuthenticationMapper authenticationMapper = applicationContext.getBean(AuthenticationMapper.class);
            String json = """
        {"name":"sergio","attributes":{"family_name":"del Amo","given_name":"Sergio","roles":["ROLE_USER"]}}""";
            Authentication authentication = authenticationMapper.read(json);
            Authentication expected = Authentication.build(
                "sergio",
                List.of("ROLE_USER"),
                Map.of("family_name", "del Amo", "given_name", "Sergio", "roles", List.of("ROLE_USER"))
            );
            assertNotNull(authentication);
            assertEquals(expected.getName(), authentication.getName());
            assertEquals(expected.getRoles().stream().toList(), authentication.getRoles().stream().toList());
            assertEquals(expected.getAttributes(), authentication.getAttributes());
        }
    }

    @Test
    void testAuthenticationMapperWithCustomRolesName() throws IOException {
        try (ApplicationContext applicationContext = ApplicationContext.run(
            Map.of("micronaut.security.token.roles-name", "authorities"))
        ) {
            AuthenticationMapper authenticationMapper = applicationContext.getBean(AuthenticationMapper.class);
            String json = """
        {"name":"sergio","attributes":{"family_name":"del Amo","given_name":"Sergio","authorities":["ROLE_USER"]}}""";
            Authentication authentication = authenticationMapper.read(json);
            Authentication expected = Authentication.build(
                "sergio",
                List.of("ROLE_USER"),
                Map.of("family_name", "del Amo", "given_name", "Sergio", "rolesKey", "authorities", "authorities", List.of("ROLE_USER"))
            );
            assertNotNull(authentication);
            assertEquals(expected.getName(), authentication.getName());
            assertEquals(expected.getRoles().stream().toList(), authentication.getRoles().stream().toList());
            assertEquals(expected.getAttributes(), authentication.getAttributes());
        }
    }

}
