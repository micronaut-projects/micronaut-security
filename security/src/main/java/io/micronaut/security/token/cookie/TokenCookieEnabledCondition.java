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
package io.micronaut.security.token.cookie;

import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;
import io.micronaut.core.value.PropertyResolver;
import io.micronaut.security.authentication.CookieBasedAuthenticationModeCondition;

/**
 * Condition that enables access-token cookie reading for cookie authentication modes or explicit opt-in.
 */
final class TokenCookieEnabledCondition implements Condition {

    private final CookieBasedAuthenticationModeCondition cookieBasedAuthenticationModeCondition =
        new CookieBasedAuthenticationModeCondition();

    @Override
    public boolean matches(ConditionContext context) {
        PropertyResolver propertyResolver = context.getBeanContext().getBean(PropertyResolver.class);
        String propertyName = TokenCookieConfigurationProperties.PREFIX + ".enabled";
        boolean explicitCookieTokenReaderOptIn = propertyResolver.containsProperty(propertyName)
            && propertyResolver.get(propertyName, Boolean.class).orElse(false);
        return explicitCookieTokenReaderOptIn || cookieBasedAuthenticationModeCondition.matches(context);
    }
}
