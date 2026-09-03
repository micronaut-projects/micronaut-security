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
package io.micronaut.security.csp.conf.scriptSrcAttr;

import io.micronaut.security.csp.conf.InlineSourceListDirectiveConfigurationProperties;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties;

import io.micronaut.context.annotation.ConfigurationProperties;

/**
 * Mutable properties for {@link ScriptSrcAttrConfiguration}.
 *
 * @since 5.4.0
 */
@ConfigurationProperties(ContentSecurityPolicyConfigurationProperties.PREFIX + ".script-src-attr")
public class ScriptSrcAttrConfigurationProperties extends InlineSourceListDirectiveConfigurationProperties implements ScriptSrcAttrConfiguration {
    /** Creates the {@code script-src-attr} configuration with its secure defaults. */
    public ScriptSrcAttrConfigurationProperties() {
    }
}
