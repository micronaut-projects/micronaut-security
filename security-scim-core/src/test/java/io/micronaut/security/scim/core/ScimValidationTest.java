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

import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
class ScimValidationTest {

    @Test
    void validatesRequiredUserAndGroupAttributes(Validator validator) {
        User user = new User();
        assertFalse(validator.validate(user).isEmpty());

        user.setUserName("bjensen@example.com");
        assertTrue(validator.validate(user).isEmpty());

        Group group = new Group();
        assertFalse(validator.validate(group).isEmpty());

        group.setDisplayName("Tour Guides");
        assertTrue(validator.validate(group).isEmpty());
    }

    @Test
    void validatesRequiredDiscoveryAttributes(Validator validator) {
        ServiceProviderConfig config = new ServiceProviderConfig();
        assertFalse(validator.validate(config).isEmpty());

        config.setPatch(new SupportedFeature(true));
        config.setBulk(new BulkFeature(true, 100, 1024));
        config.setFilter(new FilterFeature(true, 100));
        config.setChangePassword(new SupportedFeature(true));
        config.setSort(new SupportedFeature(true));
        config.setEtag(new SupportedFeature(true));
        config.setAuthenticationSchemes(java.util.List.of(new AuthenticationScheme(
            AuthenticationScheme.HTTP_BASIC,
            "HTTP Basic",
            "HTTP Basic authentication",
            "https://www.rfc-editor.org/rfc/rfc7617",
            null
        )));

        assertTrue(validator.validate(config).isEmpty());
    }
}
