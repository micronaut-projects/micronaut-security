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
package io.micronaut.security.csp.report;

import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.csp.conf.reportto.ReportToConfigurationProperties;

/**
 * Matches when {@code micronaut.security.csp.report-to.enabled} is true, with the value converted the
 * way the configuration binds it for the policy generator, so that {@code TRUE}, {@code yes} or
 * {@code on} register the report endpoint whenever the policy contains {@code report-to}.
 */
@Internal
final class ReportToEnabledCondition implements Condition {
    /**
     * The property that enables the {@code report-to} directive.
     */
    static final String PROPERTY = ReportToConfigurationProperties.PREFIX + ".enabled";

    @Override
    public boolean matches(ConditionContext context) {
        if (context.getProperty(PROPERTY, Boolean.class).orElse(Boolean.FALSE)) {
            return true;
        }
        context.fail(PROPERTY + " is not true");
        return false;
    }
}
