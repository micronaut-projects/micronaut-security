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
package io.micronaut.security.csp;

import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;
import io.micronaut.core.annotation.Internal;

import java.util.Locale;
import java.util.Set;

/**
 * Matches unless a toggle property is set to a value that turns it off.
 *
 * <p>The value is compared without case, so {@code TRUE}, {@code yes} or {@code on}, for example from
 * an environment variable, keep the toggle on, and {@code FALSE}, {@code no}, {@code n} or {@code off}
 * turn it off, as they do for a bound boolean. Any other value keeps the toggle on: a mistyped toggle, such as {@code ture}, must not
 * silently remove the response header.</p>
 *
 * <p>The condition reads the property instead of the bound {@code isEnabled()} of the configuration
 * bean, because boolean binding converts every unknown value, typos included, to {@code false}.</p>
 *
 * @since 5.6.0
 */
@Internal
public abstract class AbstractToggleCondition implements Condition {
    /**
     * The values that turn the toggle off, compared without case.
     */
    private static final Set<String> DISABLED_VALUES = Set.of("false", "no", "n", "off");

    private final String property;

    /**
     * Creates the condition for a toggle property.
     *
     * @param property the property that turns the toggle off
     */
    protected AbstractToggleCondition(String property) {
        this.property = property;
    }

    @Override
    public final boolean matches(ConditionContext context) {
        String value = context.getProperty(property, String.class).orElse(null);
        if (value == null || !DISABLED_VALUES.contains(value.trim().toLowerCase(Locale.ROOT))) {
            return true;
        }
        context.fail(property + " is false");
        return false;
    }
}
