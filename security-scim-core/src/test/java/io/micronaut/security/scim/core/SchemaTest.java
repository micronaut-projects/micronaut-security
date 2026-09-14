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
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
class SchemaTest {
    @Inject
    BeanContext beanContext;

    @Inject
    Validator validator;

    @Inject
    JsonMapper jsonMapper;

    @Test
    void validatesConstraints() {
        AttributeDefinition attribute = new AttributeDefinition(
            "userName", AttributeType.STRING, null, false, null, true, null, false,
            Mutability.READ_WRITE, Returned.DEFAULT, Uniqueness.SERVER, null);
        Schema valid = new Schema();
        valid.setId(SchemaUris.USER);
        valid.setAttributes(List.of(attribute));
        assertTrue(validator.validate(valid).isEmpty());

        Set<String> invalidProperties = validator.validate(new Schema()).stream()
            .map(violation -> violation.getPropertyPath().toString())
            .collect(Collectors.toSet());
        assertEquals(Set.of("id", "attributes"), invalidProperties);
    }

    @Test
    void deserializesRfcExample() throws IOException {
        Schema schema = jsonMapper.readValue("""
            {
              "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
              "id": "urn:ietf:params:scim:schemas:core:2.0:User",
              "name": "User",
              "description": "User Account",
              "attributes": [
                {
                  "name": "userName",
                  "type": "string",
                  "multiValued": false,
                  "description": "Unique identifier for the User",
                  "required": true,
                  "caseExact": false,
                  "mutability": "readWrite",
                  "returned": "default",
                  "uniqueness": "server"
                }
              ]
            }
            """, Schema.class);

        assertEquals(SchemaUris.USER, schema.getId());
        assertEquals("User", schema.getName());
        assertEquals("userName", schema.getAttributes().getFirst().name());
    }

    @Test
    void isDeserializable() {
        SerdeIntrospections introspections = assertDoesNotThrow(() -> beanContext.getBean(SerdeIntrospections.class));
        assertDoesNotThrow(() -> introspections.getDeserializableIntrospection(Argument.of(Schema.class)));
    }

    @Test
    void isSerializable() {
        SerdeIntrospections introspections = assertDoesNotThrow(() -> beanContext.getBean(SerdeIntrospections.class));
        assertDoesNotThrow(() -> introspections.getSerializableIntrospection(Argument.of(Schema.class)));
    }

    @Test
    void isAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(Schema.class));
    }
}
