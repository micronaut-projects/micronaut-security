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
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfiguration;
import io.micronaut.security.csp.conf.scriptSrc.ScriptSrcConfiguration;

import java.util.StringJoiner;

/**
 * Adds the Content Security Policy generated for a request to its response.
 *
 * <p>A request filter first creates the nonce used by nonce-based script policies. The response
 * filter then writes the generated policy only when the application has not already supplied the
 * selected CSP response header.</p>
 *
 * @author Sergio del Amo
 */
@Requires(classes = ServerFilter.class)
@Internal
@ServerFilter(ServerFilter.MATCH_ALL_PATTERN)
final class ContentSecurityPolicyFilter {
    private final ContentSecurityPolicyGenerator cspGenerator;
    private final ContentSecurityPolicyConfiguration cspConfiguration;
    private final ScriptSrcConfiguration scriptSrcConfiguration;
    private final ContentSecurityPolicyNonceGenerator cspNonceGenerator;

    /**
     * @param cspGenerator generates the directives to write to the response
     * @param cspConfiguration configures how the policy is written
     * @param scriptSrcConfiguration configures nonce generation for {@code script-src}
     * @param cspNonceGenerator generates per-response CSP nonces
     */
    ContentSecurityPolicyFilter(ContentSecurityPolicyGenerator cspGenerator,
                                ContentSecurityPolicyConfiguration cspConfiguration,
                                ScriptSrcConfiguration scriptSrcConfiguration,
                                ContentSecurityPolicyNonceGenerator cspNonceGenerator) {
        this.cspGenerator = cspGenerator;
        this.cspConfiguration = cspConfiguration;
        this.scriptSrcConfiguration = scriptSrcConfiguration;
        this.cspNonceGenerator = cspNonceGenerator;
    }

    /**
     * Generates and stores the nonce before view rendering and response policy generation.
     *
     * @param request the current request
     */
    @RequestFilter
    void generateNonce(HttpRequest<?> request) {
        if (scriptSrcConfiguration.isEnabled() && scriptSrcConfiguration.isNonce()) {
            request.setAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, cspNonceGenerator.generateNonce(request));
        }
    }

    /**
     * Writes the enforcing or report-only CSP header unless application code already set it.
     *
     * @param request the current request
     * @param response the response to which the header may be added
     */
    @ResponseFilter
    void filter(HttpRequest<?> request, MutableHttpResponse<?> response) {
        String headerName = cspConfiguration.isReportOnly()
            ? ContentSecurityPolicyHeaders.CONTENT_SECURITY_POLICY_REPORT_ONLY : ContentSecurityPolicyHeaders.CONTENT_SECURITY_POLICY;
        boolean responseSetsAlreadyCspHeader = response.getHeaders().contains(headerName);
        if (!responseSetsAlreadyCspHeader) {
            response.header(headerName, cspValue(request));
        }
    }

    /**
     * Serializes the ordered request policy as one HTTP header value.
     *
     * @param request the request for which to generate the policy
     * @return the semicolon-separated CSP header value
     */
    private String cspValue(HttpRequest<?> request) {
        // CSP directives are separated with semicolons; source expressions within each directive
        // have already been serialized by the generator.
        StringJoiner directives = new StringJoiner("; ");
        for (ContentSecurityPolicyDirective directive : cspGenerator.contentSecurityPolicy(request)) {
            directives.add(directive.toString());
        }
        return directives.toString();
    }
}
