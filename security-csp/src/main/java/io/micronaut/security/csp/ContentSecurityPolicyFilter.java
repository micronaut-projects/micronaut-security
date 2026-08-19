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
package io.micronaut.security.csp;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.RequestFilter;
import io.micronaut.http.annotation.ResponseFilter;
import io.micronaut.http.annotation.ServerFilter;

import java.util.StringJoiner;

/**
 * Adds the Content Security Policy generated for a request to its response.
 *
 * @author Sergio del Amo
 */
@Requires(classes = ServerFilter.class)
@Internal
@ServerFilter(ServerFilter.MATCH_ALL_PATTERN)
final class ContentSecurityPolicyFilter {
    private static final String CONTENT_SECURITY_POLICY = "Content-Security-Policy";
    private static final String CONTENT_SECURITY_POLICY_REPORT_ONLY = "Content-Security-Policy-Report-Only";
    private final ContentSecurityPolicyGenerator cspGenerator;
    private final ContentSecurityPolicyConfiguration cspConfiguration;
    private final CspNonceGenerator cspNonceGenerator;

    /**
     * @param cspGenerator generates the directives to write to the response
     * @param cspConfiguration configures how the policy is written
     * @param cspNonceGenerator generates per-response CSP nonces
     */
    ContentSecurityPolicyFilter(ContentSecurityPolicyGenerator cspGenerator,
                                ContentSecurityPolicyConfiguration cspConfiguration,
                                CspNonceGenerator cspNonceGenerator) {
        this.cspGenerator = cspGenerator;
        this.cspConfiguration = cspConfiguration;
        this.cspNonceGenerator = cspNonceGenerator;
    }

    @RequestFilter
    void generateNonce(HttpRequest<?> request) {
        if (cspConfiguration.isScriptSrcNonceEnabled()) {
            request.setAttribute(CspNonceGenerator.CSP_NONCE_ATTRIBUTE, cspNonceGenerator.generateNonce(request));
        }
    }

    @ResponseFilter
    void filter(HttpRequest<?> request, MutableHttpResponse<?> response) {
        String headerName = cspConfiguration.isReportOnly()
            ? CONTENT_SECURITY_POLICY_REPORT_ONLY : CONTENT_SECURITY_POLICY;
        boolean responseSetsAlreadyCspHeader = response.getHeaders().contains(headerName);
        if (!responseSetsAlreadyCspHeader) {
            response.header(headerName, cspValue(request));
        }
    }

    private String cspValue(HttpRequest<?> request) {
        StringJoiner directives = new StringJoiner("; ");
        for (CspDirective directive : cspGenerator.contentSecurityPolicy(request)) {
            directives.add(directive.toString());
        }
        return directives.toString();
    }
}
