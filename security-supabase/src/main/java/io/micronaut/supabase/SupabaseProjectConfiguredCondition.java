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
package io.micronaut.supabase;

import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.value.PropertyResolver;

/**
 * Matches when the Supabase project is addressable: {@code supabase.url} or {@code supabase.project-id} is set.
 *
 * @since 0.0.1
 */
@Internal
final class SupabaseProjectConfiguredCondition implements Condition {

    static final String URL_PROPERTY = SupabaseConfigurationProperties.PREFIX + ".url";
    static final String PROJECT_ID_PROPERTY = SupabaseConfigurationProperties.PREFIX + ".project-id";

    @Override
    public boolean matches(ConditionContext context) {
        return context.getBeanContext() instanceof PropertyResolver properties
            && (properties.containsProperty(URL_PROPERTY) || properties.containsProperty(PROJECT_ID_PROPERTY));
    }
}
