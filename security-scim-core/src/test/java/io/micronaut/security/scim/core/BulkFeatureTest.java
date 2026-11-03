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
class BulkFeatureTest {
    @Inject
    BeanContext beanContext;

    @Inject
    Validator validator;

    @Inject
    JsonMapper jsonMapper;

    @Test
    void validatesConstraints() {
        assertTrue(validator.validate(new BulkFeature(true, 1, 1)).isEmpty());

        BulkFeature invalid = new BulkFeature(true, -1, -1);
        Set<String> invalidProperties = validator.validate(invalid).stream()
            .map(violation -> violation.getPropertyPath().toString())
            .collect(Collectors.toSet());
        assertEquals(Set.of("maxOperations", "maxPayloadSize"), invalidProperties);
    }

    @Test
    void deserializesRfcExample() throws IOException {
        BulkFeature bulk = jsonMapper.readValue("""
            {
              "supported": true,
              "maxOperations": 1000,
              "maxPayloadSize": 1048576
            }
            """, BulkFeature.class);

        assertTrue(bulk.supported());
        assertEquals(1000, bulk.maxOperations());
        assertEquals(1048576, bulk.maxPayloadSize());
    }


    @Test
    void isDeserializable() {
        SerdeIntrospections introspections = assertDoesNotThrow(() -> beanContext.getBean(SerdeIntrospections.class));
        assertDoesNotThrow(() -> introspections.getDeserializableIntrospection(Argument.of(BulkFeature.class)));
    }

    @Test
    void isSerializable() {
        SerdeIntrospections introspections = assertDoesNotThrow(() -> beanContext.getBean(SerdeIntrospections.class));
        assertDoesNotThrow(() -> introspections.getSerializableIntrospection(Argument.of(BulkFeature.class)));
    }

    @Test
    void isAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(BulkFeature.class));
    }
}
