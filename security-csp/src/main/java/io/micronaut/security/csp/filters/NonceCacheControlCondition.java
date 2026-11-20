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
import io.micronaut.core.util.StringUtils;

/**
 * Matches when a {@code Cache-Control} value is configured for responses that carry a nonce. The
 * value defaults to {@code private}; an application opts out with a blank value. It keeps
 * {@link NonceCacheControlResponseHeaderPopulator} out of the application when it would write
 * nothing. Whether any directive uses nonces is checked separately by {@link NonceEnabledCondition}.
 *
 * <p>The condition is evaluated once, when the bean is loaded.</p>
 */
@Internal
final class NonceCacheControlCondition implements Condition {
    @Override
    public boolean matches(ConditionContext context) {
        if (context.findBean(ContentSecurityPolicyFilterConfiguration.class)
            .map(ContentSecurityPolicyFilterConfiguration::getNonceCacheControl)
            .filter(StringUtils::hasText)
            .isPresent()) {
            return true;
        }
        context.fail("No Cache-Control value is configured for responses that carry a Content Security Policy nonce");
        return false;
    }
}
