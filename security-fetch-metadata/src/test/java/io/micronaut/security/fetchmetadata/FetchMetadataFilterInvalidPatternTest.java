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

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.exceptions.BeanInstantiationException;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.util.StringUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

class FetchMetadataFilterInvalidPatternTest {

    @ParameterizedTest
    @ValueSource(strings = {"", "   "})
    void rejectsAnEmptyOrBlankPatternDuringContextStartup(String pattern) {
        BeanInstantiationException exception = assertThrows(BeanInstantiationException.class, () -> {
            try (ApplicationContext ignored = ApplicationContext.run(Map.of(
                FetchMetadataFilterConfigurationProperties.PREFIX + ".pattern", pattern))) {
                // The @Context configuration bean must be initialized during startup.
            }
        });
        assertInstanceOf(ConfigurationException.class, rootCause(exception));
    }

    @Test
    void ignoresABlankPatternWhenTheFilterIsDisabled() {
        try (ApplicationContext context = ApplicationContext.run(Map.of(
            FetchMetadataFilterConfigurationProperties.PREFIX + ".pattern", "   ",
            FetchMetadataFilterConfigurationProperties.PROPERTY_ENABLED, StringUtils.FALSE))) {
            assertFalse(context.containsBean(FetchMetadataFilterConfiguration.class));
        }
    }

    private static Throwable rootCause(Throwable exception) {
        Throwable cause = exception;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        return cause;
    }
}
