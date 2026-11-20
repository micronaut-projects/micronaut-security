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

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.RequestFilter;
import io.micronaut.http.annotation.ServerFilter;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;

/**
 * Generates the Content Security Policy nonce for a request. Every directive that uses nonces,
 * such as {@code script-src} or {@code style-src}, shares the same nonce.
 *
 * <p>The filter is only loaded when an enabled directive uses nonces: see {@link NonceEnabledCondition}.
 * The CSP response header is written by {@link ContentSecurityPolicyResponseHeaderPopulator}.</p>
 *
 * @author Sergio del Amo
 */
@Internal
@Requires(condition = NonceEnabledCondition.class)
@ServerFilter("${" + ContentSecurityPolicyFilterConfigurationProperties.PREFIX + ".pattern:" + ServerFilter.MATCH_ALL_PATTERN + "}")
final class ContentSecurityPolicyNonceFilter {
    private final ContentSecurityPolicyNonceGenerator cspNonceGenerator;

    /**
     * Creates the server filter that generates request nonces.
     *
     * @param cspNonceGenerator generates per-response CSP nonces
     */
    ContentSecurityPolicyNonceFilter(ContentSecurityPolicyNonceGenerator cspNonceGenerator) {
        this.cspNonceGenerator = cspNonceGenerator;
    }

    /**
     * Generates and stores the nonce before view rendering and response policy generation.
     *
     * @param request the current request
     */
    @RequestFilter
    void generateNonce(HttpRequest<?> request) {
        request.setAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, cspNonceGenerator.generateNonce(request));
    }
}
