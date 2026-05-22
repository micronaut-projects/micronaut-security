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
package io.micronaut.security.html;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.security.config.SecurityConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * {@link HtmlSanitizerConfiguration} implementation.
 *
 * @author Sergio del Amo
 * @since 5.1.0
 */
@ConfigurationProperties(HtmlSanitizerConfigurationProperties.PREFIX)
public class HtmlSanitizerConfigurationProperties implements HtmlSanitizerConfiguration {

    /**
     * The configuration prefix.
     */
    public static final String PREFIX = SecurityConfigurationProperties.PREFIX + ".html-sanitizer";

    /**
     * The default enabled value.
     */
    public static final boolean DEFAULT_ENABLED = true;

    private boolean enabled = DEFAULT_ENABLED;
    private List<HtmlSanitizerPolicy> policies = new ArrayList<>(List.of(
        HtmlSanitizerPolicy.BLOCKS,
        HtmlSanitizerPolicy.FORMATTING,
        HtmlSanitizerPolicy.LINKS
    ));

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether the OWASP-backed HTML sanitizer is enabled.
     *
     * @param enabled True if the sanitizer is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public List<HtmlSanitizerPolicy> getPolicies() {
        return List.copyOf(policies);
    }

    /**
     * Sets the OWASP sanitizer policies to combine.
     *
     * @param policies The sanitizer policies
     */
    public void setPolicies(List<HtmlSanitizerPolicy> policies) {
        this.policies = new ArrayList<>(policies);
    }
}
