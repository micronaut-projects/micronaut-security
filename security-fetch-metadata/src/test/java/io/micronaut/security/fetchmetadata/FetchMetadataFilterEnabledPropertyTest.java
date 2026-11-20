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
import io.micronaut.core.util.StringUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The filter is a security control, so only an explicit {@code false} turns it off. A mistyped
 * or non-boolean value must not disable it silently.
 */
class FetchMetadataFilterEnabledPropertyTest {

    @ParameterizedTest
    @ValueSource(strings = {"true", "ture", "on", "1", "FALSE", "off"})
    void keepsTheFilterForAnyValueOtherThanFalse(String value) {
        try (ApplicationContext context = ApplicationContext.run(Map.of(
            FetchMetadataFilterConfiguration.PROPERTY_ENABLED, value))) {
            assertTrue(context.containsBean(FetchMetadataFilter.class));
            assertTrue(context.containsBean(FetchMetadataFilterConfiguration.class));
        }
    }

    @Test
    void removesTheFilterWhenThePropertyIsFalse() {
        try (ApplicationContext context = ApplicationContext.run(Map.of(
            FetchMetadataFilterConfiguration.PROPERTY_ENABLED, StringUtils.FALSE))) {
            assertFalse(context.containsBean(FetchMetadataFilter.class));
            assertFalse(context.containsBean(FetchMetadataFilterConfiguration.class));
        }
    }

    @Test
    void keepsTheFilterWhenThePropertyIsAbsent() {
        try (ApplicationContext context = ApplicationContext.run()) {
            assertTrue(context.containsBean(FetchMetadataFilter.class));
        }
    }
}
