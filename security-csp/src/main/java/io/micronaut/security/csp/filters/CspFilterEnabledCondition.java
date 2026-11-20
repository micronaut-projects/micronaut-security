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
package io.micronaut.security.csp.filters;

import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;
import io.micronaut.core.annotation.Internal;

import java.util.Locale;
import java.util.Set;

/**
 * Enables the filter package unless {@code micronaut.security.csp.filter.enabled} is false.
 *
 * <p>The value is compared without case, so {@code TRUE},
 * {@code yes} or {@code on} keep the header, and {@code FALSE}, {@code no} or {@code off} remove it.
 * Any other value keeps the header: a mistyped toggle must not silently remove it.</p>
 */
@Internal
final class CspFilterEnabledCondition implements Condition {
    /**
     * The values that turn the toggle off, compared without case.
     */
    private static final Set<String> DISABLED_VALUES = Set.of("false", "no", "off");

    @Override
    public boolean matches(ConditionContext context) {
        String value = context.getProperty(ContentSecurityPolicyFilterConfigurationProperties.PROPERTY_ENABLED, String.class).orElse(null);
        if (value == null || !DISABLED_VALUES.contains(value.trim().toLowerCase(Locale.ROOT))) {
            return true;
        }
        context.fail(ContentSecurityPolicyFilterConfigurationProperties.PROPERTY_ENABLED + " is false");
        return false;
    }
}
