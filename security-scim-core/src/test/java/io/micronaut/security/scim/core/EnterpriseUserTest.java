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
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
class EnterpriseUserTest {
    @Inject
    BeanContext beanContext;

    @Inject
    Validator validator;

    @Inject
    JsonMapper jsonMapper;

    @Test
    void hasNoValidationViolations() {
        EnterpriseUser value = new EnterpriseUser(null, null, null, null, null, null);
        Set<ConstraintViolation<EnterpriseUser>> violations = validator.validate(value);
        assertTrue(violations.isEmpty());
    }

    @Test
    void deserializesRfcExample() throws IOException {
        EnterpriseUser enterpriseUser = jsonMapper.readValue("""
            {
              "employeeNumber": "701984",
              "costCenter": "4130",
              "organization": "Universal Studios",
              "division": "Theme Park",
              "department": "Tour Operations",
              "manager": {
                "value": "26118915-6090-4610-87e4-49d8ca9f808d",
                "$ref": "../Users/26118915-6090-4610-87e4-49d8ca9f808d",
                "displayName": "John Smith"
              }
            }
            """, EnterpriseUser.class);

        assertEquals("701984", enterpriseUser.employeeNumber());
        assertEquals("John Smith", enterpriseUser.manager().displayName());
    }


    @Test
    void isDeserializable() {
        SerdeIntrospections introspections = assertDoesNotThrow(() -> beanContext.getBean(SerdeIntrospections.class));
        assertDoesNotThrow(() -> introspections.getDeserializableIntrospection(Argument.of(EnterpriseUser.class)));
    }

    @Test
    void isSerializable() {
        SerdeIntrospections introspections = assertDoesNotThrow(() -> beanContext.getBean(SerdeIntrospections.class));
        assertDoesNotThrow(() -> introspections.getSerializableIntrospection(Argument.of(EnterpriseUser.class)));
    }

    @Test
    void isAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(EnterpriseUser.class));
    }
}
