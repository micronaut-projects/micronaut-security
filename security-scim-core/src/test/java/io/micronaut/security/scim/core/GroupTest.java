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

import io.micronaut.context.BeanContext;
import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.SerdeIntrospections;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
class GroupTest {
    @Inject
    BeanContext beanContext;

    @Inject
    Validator validator;

    @Inject
    JsonMapper jsonMapper;

    @Test
    void validatesConstraints() {
        Group valid = new Group();
        valid.setDisplayName("Tour Guides");
        assertTrue(validator.validate(valid).isEmpty());

        Set<String> invalidProperties = validator.validate(new Group()).stream()
            .map(violation -> violation.getPropertyPath().toString())
            .collect(Collectors.toSet());
        assertEquals(Set.of("displayName"), invalidProperties);
    }

    @Test
    void deserializesRfcExample() throws IOException {
        Group group = jsonMapper.readValue("""
            {
              "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
              "id": "e9e30dba-f08f-4109-8486-d5c6a331660a",
              "displayName": "Tour Guides",
              "members": [
                {
                  "value": "2819c223-7f76-453a-919d-413861904646",
                  "$ref": "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
                  "display": "Babs Jensen"
                }
              ],
              "meta": {
                "resourceType": "Group",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "location": "https://example.com/v2/Groups/e9e30dba-f08f-4109-8486-d5c6a331660a"
              }
            }
            """, Group.class);

        assertEquals("Tour Guides", group.getDisplayName());
        assertEquals("Babs Jensen", group.getMembers().getFirst().display());
        assertEquals("Group", group.getMeta().resourceType());
    }

    @Test
    void isDeserializable() {
        SerdeIntrospections introspections = assertDoesNotThrow(() -> beanContext.getBean(SerdeIntrospections.class));
        assertDoesNotThrow(() -> introspections.getDeserializableIntrospection(Argument.of(Group.class)));
    }

    @Test
    void isSerializable() {
        SerdeIntrospections introspections = assertDoesNotThrow(() -> beanContext.getBean(SerdeIntrospections.class));
        assertDoesNotThrow(() -> introspections.getSerializableIntrospection(Argument.of(Group.class)));
    }

    @Test
    void isAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(Group.class));
    }
}

