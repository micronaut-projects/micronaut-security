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
package io.micronaut.security.fetchmetadata;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.util.StringUtils;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = FetchMetadataFilterConfigurationProperties.PROPERTY_ENABLED, value = StringUtils.FALSE)
@Property(name = FetchMetadataFilterConfigurationProperties.PREFIX + ".pattern", value = "/api/**")
@MicronautTest(startApplication = false)
class FetchMetadataFilterConfigurationPropertiesTest {

    @Test
    void bindsFilterConfiguration(FetchMetadataFilterConfiguration configuration) {
        assertFalse(configuration.isEnabled());
        assertEquals("/api/**", configuration.getPattern());
    }

    @Test
    void usesDocumentedDefaultsAndRejectsEmptyPatterns() {
        FetchMetadataFilterConfigurationProperties configuration =
            new FetchMetadataFilterConfigurationProperties();

        assertTrue(configuration.isEnabled());
        assertEquals("/**", configuration.getPattern());

        assertThrows(ConfigurationException.class, () -> configuration.setPattern(""));
        assertThrows(ConfigurationException.class, () -> configuration.setPattern("   "));
        assertEquals("/**", configuration.getPattern());
    }
}
