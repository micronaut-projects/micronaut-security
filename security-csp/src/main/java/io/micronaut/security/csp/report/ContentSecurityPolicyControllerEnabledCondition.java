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

import io.micronaut.core.annotation.Internal;
import io.micronaut.security.csp.AbstractToggleCondition;

/**
 * Registers the report controller unless {@code micronaut.security.csp.report-to.controller.enabled}
 * is false; see {@link AbstractToggleCondition} for the accepted values.
 */
@Internal
final class ContentSecurityPolicyControllerEnabledCondition extends AbstractToggleCondition {
    /**
     * The property that disables the report controller.
     */
    static final String PROPERTY = ContentSecurityPolicyControllerConfigurationProperties.PREFIX + ".enabled";

    ContentSecurityPolicyControllerEnabledCondition() {
        super(PROPERTY);
    }
}
