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

import io.micronaut.context.annotation.Context;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.Internal;

/**
 * Fails application startup when the CSP filter of Micronaut Views is enabled as well. Both filters
 * write a CSP header and the {@code cspNonce} request attribute, so the header of Micronaut Views,
 * whose nonce may come from {@link java.util.Random}, could replace this module's policy, or one
 * filter's nonce could end up in the other's header.
 */
@Requires(condition = ViewsCspConflictCheck.ViewsCspEnabledCondition.class)
@Context
@Internal
final class ViewsCspConflictCheck {
    /**
     * The property that enables the CSP filter of Micronaut Views.
     */
    static final String VIEWS_CSP_ENABLED = "micronaut.views.csp.enabled";

    /**
     * Fails startup, because the bean only exists while both CSP filters are enabled.
     *
     * @throws ConfigurationException always
     */
    ViewsCspConflictCheck() {
        throw new ConfigurationException("Micronaut Views CSP and micronaut-security-csp are both enabled, and both write the cspNonce "
            + "request attribute and a Content-Security-Policy header. Set " + VIEWS_CSP_ENABLED + "=false.");
    }

    /**
     * Matches when the CSP filter of Micronaut Views is enabled, with the value converted the way
     * the configuration binds booleans, so that {@code TRUE} or {@code yes} also match.
     */
    @Internal
    static final class ViewsCspEnabledCondition implements Condition {
        @Override
        public boolean matches(ConditionContext context) {
            if (context.getProperty(VIEWS_CSP_ENABLED, Boolean.class).orElse(Boolean.FALSE)) {
                return true;
            }
            context.fail(VIEWS_CSP_ENABLED + " is not true");
            return false;
        }
    }
}
