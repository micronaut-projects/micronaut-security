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
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.security.annotation.Attribute;
import io.micronaut.security.annotation.RunAs;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertThrows;

class RunAsInvalidConfigurationTest {

    @Test
    void nameCannotBeBlank() {
        try (ApplicationContext context = ApplicationContext.run(Map.of("spec.name", "RunAsInvalidConfigurationTest"))) {
            BlankNameService service = context.getBean(BlankNameService.class);

            assertThrows(ConfigurationException.class, service::call);
        }
    }

    @Test
    void rolesCannotBeBlank() {
        try (ApplicationContext context = ApplicationContext.run(Map.of("spec.name", "RunAsInvalidConfigurationTest"))) {
            BlankRoleService service = context.getBean(BlankRoleService.class);

            assertThrows(ConfigurationException.class, service::call);
        }
    }

    @Test
    void attributeKeysCannotBeBlank() {
        try (ApplicationContext context = ApplicationContext.run(Map.of("spec.name", "RunAsInvalidConfigurationTest"))) {
            BlankAttributeKeyService service = context.getBean(BlankAttributeKeyService.class);

            assertThrows(ConfigurationException.class, service::call);
        }
    }

    @RunAs(name = "")
    @Requires(property = "spec.name", value = "RunAsInvalidConfigurationTest")
    @Singleton
    static class BlankNameService {
        String call() {
            return "ok";
        }
    }

    @RunAs(name = "aegon", roles = " ")
    @Requires(property = "spec.name", value = "RunAsInvalidConfigurationTest")
    @Singleton
    static class BlankRoleService {
        String call() {
            return "ok";
        }
    }

    @RunAs(name = "aegon", attributes = @Attribute(key = " ", value = "Targaryen"))
    @Requires(property = "spec.name", value = "RunAsInvalidConfigurationTest")
    @Singleton
    static class BlankAttributeKeyService {
        String call() {
            return "ok";
        }
    }
}
