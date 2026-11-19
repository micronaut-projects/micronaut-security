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
import io.micronaut.core.util.Toggleable;
import io.micronaut.security.csp.conf.NonceConfiguration;

/**
 * Matches when at least one enabled Content Security Policy directive, such as {@code script-src}
 * or {@code style-src}, uses nonces. It keeps {@link ContentSecurityPolicyFilter} out of the
 * filter chain of applications that do not use nonces.
 *
 * @author Sergio del Amo
 * @since 5.6.0
 */
@Internal
final class NonceEnabledCondition implements Condition {

    @Override
    public boolean matches(ConditionContext context) {
        if (context.getBeansOfType(NonceConfiguration.class).stream().anyMatch(NonceEnabledCondition::isNonceEnabled)) {
            return true;
        }
        context.fail("No enabled Content Security Policy directive uses nonces");
        return false;
    }

    private static boolean isNonceEnabled(NonceConfiguration configuration) {
        return configuration.isNonce() && (!(configuration instanceof Toggleable toggleable) || toggleable.isEnabled());
    }
}
