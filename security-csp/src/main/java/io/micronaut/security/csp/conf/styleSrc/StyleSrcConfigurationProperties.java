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
package io.micronaut.security.csp.conf.styleSrc;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties;
import io.micronaut.security.csp.conf.InlineSourceListDirectiveConfigurationProperties;

/**
 * Mutable properties for {@link StyleSrcConfiguration}.
 *
 * <p>Nonce source expressions are disabled by default, leaving the inherited {@code 'none'} source
 * expression as the secure default.</p>
 *
 * @since 5.4.0
 */
@ConfigurationProperties(ContentSecurityPolicyConfigurationProperties.PREFIX + ".style-src")
public class StyleSrcConfigurationProperties extends InlineSourceListDirectiveConfigurationProperties implements StyleSrcConfiguration {
    private boolean nonce;

    @Override
    public boolean isNonce() {
        return nonce;
    }

    /**
     * @param nonce whether a nonce source expression is generated for this directive; defaults to {@code false}
     */
    public void setNonce(boolean nonce) {
        this.nonce = nonce;
    }
}
