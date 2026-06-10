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
    void equalsAndHashCodeTest() throws IOException {
        assertEquals(new ServerAuthentication("sergio",
            List.of("ROLE_USER"),
            Map.of("family_name", "del Amo", "given_name", "Sergio")), new ServerAuthentication("sergio",
            List.of("ROLE_USER"),
            Map.of("family_name", "del Amo", "given_name", "Sergio")));
    }
}
