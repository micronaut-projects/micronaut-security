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
package io.micronaut.security.scim.server.protocol;

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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
class ScimBulkResponseTest {
    @Inject
    BeanContext beanContext;

    @Inject
    Validator validator;

    @Inject
    JsonMapper jsonMapper;

    @Test
    void hasNoValidationViolations() {
        ScimBulkResponseOperation operation = new ScimBulkResponseOperation(
            ScimBulkMethod.POST, "qwerty", "W/\"1\"", "https://example.com/v2/Users/2819c223",
            null, "201");

        assertTrue(validator.validate(ScimBulkResponse.of(List.of(operation))).isEmpty());
    }

    @Test
    void deserializesRfcExample() throws IOException {
        ScimBulkResponse response = jsonMapper.readValue("""
            {
              "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkResponse"],
              "Operations": [{
                "method": "POST",
                "bulkId": "qwerty",
                "version": "W/\\\"1\\\"",
                "location": "https://example.com/v2/Users/2819c223",
                "status": "201"
              }]
            }
            """, ScimBulkResponse.class);

        assertEquals(ScimMessageSchemas.BULK_RESPONSE, response.schemas().getFirst());
        assertEquals("201", response.operations().getFirst().status());
        assertEquals(ScimBulkMethod.POST, response.operations().getFirst().method());
    }

    @Test
    void isDeserializable() {
        SerdeIntrospections introspections = assertDoesNotThrow(() -> beanContext.getBean(SerdeIntrospections.class));
        assertDoesNotThrow(() -> introspections.getDeserializableIntrospection(Argument.of(ScimBulkResponse.class)));
    }

    @Test
    void isSerializable() {
        SerdeIntrospections introspections = assertDoesNotThrow(() -> beanContext.getBean(SerdeIntrospections.class));
        assertDoesNotThrow(() -> introspections.getSerializableIntrospection(Argument.of(ScimBulkResponse.class)));
    }

    @Test
    void isAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(ScimBulkResponse.class));
    }
}
