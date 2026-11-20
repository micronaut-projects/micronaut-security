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
package io.micronaut.security.csp.conf.requiretrustedtypesfor;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties;

/**
 * Binds configuration for the {@code require-trusted-types-for} directive.
 *
 * @since 5.6.0
 */
@Internal
@ConfigurationProperties(ContentSecurityPolicyConfigurationProperties.PROPERTY_REQUIRE_TRUSTED_TYPES_FOR)
public class RequireTrustedTypesForConfigurationProperties implements RequireTrustedTypesForConfiguration {
    private static final String DEFAULT_VALUE = "'script'";
    private boolean enabled = true;
    private String value = DEFAULT_VALUE;

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Whether to write the require-trusted-types-for directive, which makes browsers reject strings
     * assigned to DOM injection sinks such as innerHTML unless they come from a Trusted Types policy.
     * Default: true.
     *
     * @param enabled whether the {@code require-trusted-types-for} directive is included in the policy
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public String getValue() {
        return value;
    }

    /**
     * Sink group written in the require-trusted-types-for directive, including its single quotes. Default: 'script'.
     *
     * @param value the sink group required to use Trusted Types
     */
    public void setValue(String value) {
        this.value = value;
    }
}
