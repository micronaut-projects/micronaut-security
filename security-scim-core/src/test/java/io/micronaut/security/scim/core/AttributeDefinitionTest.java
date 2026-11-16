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
class AttributeDefinitionTest {
    @Inject
    BeanContext beanContext;

    @Inject
    Validator validator;

    @Inject
    JsonMapper jsonMapper;

    @Test
    void validatesConstraints() {
        AttributeDefinition valid = new AttributeDefinition(
            "serialNumber", AttributeType.STRING, null, false, null, false, null, false,
            Mutability.READ_WRITE, Returned.DEFAULT, Uniqueness.NONE, null);
        assertTrue(validator.validate(valid).isEmpty());

        AttributeDefinition invalid = new AttributeDefinition(
            "", null, null, false, null, false, null, false, null, null, null, null);
        Set<String> invalidProperties = validator.validate(invalid).stream()
            .map(violation -> violation.getPropertyPath().toString())
            .collect(Collectors.toSet());
        assertEquals(Set.of("name", "type", "mutability", "returned", "uniqueness"), invalidProperties);
    }

    @Test
    void deserializesRfcExample() throws IOException {
        AttributeDefinition attribute = jsonMapper.readValue("""
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
            """, AttributeDefinition.class);

        assertEquals("userName", attribute.name());
        assertEquals(AttributeType.STRING, attribute.type());
        assertEquals(Mutability.READ_WRITE, attribute.mutability());
        assertEquals(Returned.DEFAULT, attribute.returned());
        assertEquals(Uniqueness.SERVER, attribute.uniqueness());
    }


    @Test
    void isDeserializable() {
        SerdeIntrospections introspections = assertDoesNotThrow(() -> beanContext.getBean(SerdeIntrospections.class));
        assertDoesNotThrow(() -> introspections.getDeserializableIntrospection(Argument.of(AttributeDefinition.class)));
    }

    @Test
    void isSerializable() {
        SerdeIntrospections introspections = assertDoesNotThrow(() -> beanContext.getBean(SerdeIntrospections.class));
        assertDoesNotThrow(() -> introspections.getSerializableIntrospection(Argument.of(AttributeDefinition.class)));
    }

    @Test
    void isAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(AttributeDefinition.class));
    }
}
