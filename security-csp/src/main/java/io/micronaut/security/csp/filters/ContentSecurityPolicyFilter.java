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

import io.micronaut.core.annotation.Internal;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.RequestFilter;
import io.micronaut.http.annotation.ServerFilter;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;
import io.micronaut.security.csp.conf.scriptSrc.ScriptSrcConfiguration;

/**
 * Generates the Content Security Policy nonce for a request when nonce-based script policies are enabled.
 *
 * <p>The CSP response header is written by {@link ContentSecurityPolicyResponseHeaderPopulator}.</p>
 *
 * @author Sergio del Amo
 */
@Internal
@ServerFilter("${" + ContentSecurityPolicyFilterConfigurationProperties.PREFIX + ".pattern:" + ServerFilter.MATCH_ALL_PATTERN + "}")
final class ContentSecurityPolicyFilter {
    private final ScriptSrcConfiguration scriptSrcConfiguration;
    private final ContentSecurityPolicyNonceGenerator cspNonceGenerator;

    /**
     * Creates the server filter that generates request nonces.
     *
     * @param scriptSrcConfiguration configures nonce generation for {@code script-src}
     * @param cspNonceGenerator generates per-response CSP nonces
     */
    ContentSecurityPolicyFilter(ScriptSrcConfiguration scriptSrcConfiguration,
                                ContentSecurityPolicyNonceGenerator cspNonceGenerator) {
        this.scriptSrcConfiguration = scriptSrcConfiguration;
        this.cspNonceGenerator = cspNonceGenerator;
    }

    /**
     * Generates and stores the nonce before view rendering and response policy generation when
     * nonce support is enabled for {@code script-src}.
     *
     * @param request the current request
     */
    @RequestFilter
    void generateNonce(HttpRequest<?> request) {
        if (scriptSrcConfiguration.isEnabled() && scriptSrcConfiguration.isNonce()) {
            request.setAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, cspNonceGenerator.generateNonce(request));
        }
    }
}
