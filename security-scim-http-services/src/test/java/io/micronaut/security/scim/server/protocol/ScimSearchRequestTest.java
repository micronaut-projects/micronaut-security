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
class ScimSearchRequestTest {
    @Inject
    BeanContext beanContext;

    @Inject
    Validator validator;

    @Inject
    JsonMapper jsonMapper;

    @Test
    void hasNoValidationViolations() {
        ScimSearchRequest request = new ScimSearchRequest(
            List.of(ScimMessageSchemas.SEARCH_REQUEST), List.of("displayName", "userName"), null,
            "displayName sw \"smith\"", "userName", ScimSortOrder.ASCENDING, 1, 10);

        assertTrue(validator.validate(request).isEmpty());
    }

    @Test
    void deserializesRfcExample() throws IOException {
        ScimSearchRequest request = jsonMapper.readValue("""
            {
              "schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
              "attributes": ["displayName", "userName"],
              "filter": "displayName sw \\\"smith\\\"",
              "sortBy": "userName",
              "sortOrder": "ascending",
              "startIndex": 1,
              "count": 10
            }
            """, ScimSearchRequest.class);

        assertEquals(ScimMessageSchemas.SEARCH_REQUEST, request.schemas().getFirst());
        assertEquals(List.of("displayName", "userName"), request.attributes());
        assertEquals("displayName sw \"smith\"", request.filter());
        assertEquals(ScimSortOrder.ASCENDING, request.sortOrder());
        assertEquals(1, request.startIndex());
        assertEquals(10, request.count());
    }

    @Test
    void isDeserializable() {
        SerdeIntrospections introspections = assertDoesNotThrow(() -> beanContext.getBean(SerdeIntrospections.class));
        assertDoesNotThrow(() -> introspections.getDeserializableIntrospection(Argument.of(ScimSearchRequest.class)));
    }

    @Test
    void isSerializable() {
        SerdeIntrospections introspections = assertDoesNotThrow(() -> beanContext.getBean(SerdeIntrospections.class));
        assertDoesNotThrow(() -> introspections.getSerializableIntrospection(Argument.of(ScimSearchRequest.class)));
    }

    @Test
    void isAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(ScimSearchRequest.class));
    }
}
