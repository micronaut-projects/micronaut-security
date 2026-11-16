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
package io.micronaut.security.scim.data.entities;

import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
class ScimGroupEntityTest {

    @Inject
    Validator validator;

    @Test
    void isAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(ScimGroupEntity.class));
    }

    @Test
    void hasExpectedDataMapping() {
        EntityTestSupport.assertMappedEntity(ScimGroupEntity.class, "scim_group", "id");
    }

    @Test
    void validatesRequiredFields() {
        assertTrue(validator.validate(group("group-id", "Employees")).isEmpty());
        assertEquals(Set.of("id", "displayName"),
            EntityTestSupport.propertyPaths(validator.validate(group("", ""))));
    }

    private static ScimGroupEntity group(String id, String displayName) {
        return new ScimGroupEntity(id, null, displayName, null, null, null);
    }
}
