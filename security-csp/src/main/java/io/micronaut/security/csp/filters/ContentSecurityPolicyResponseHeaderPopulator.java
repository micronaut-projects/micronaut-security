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

import io.micronaut.context.annotation.Context;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpHeaderEntry;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.ServerFilter;
import io.micronaut.http.server.filter.ResponseHeaderPopulator;
import io.micronaut.security.csp.ContentSecurityPolicy;
import io.micronaut.security.csp.ContentSecurityPolicyGenerator;
import io.micronaut.security.csp.DefaultContentSecurityPolicyGenerator;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfiguration;
import org.jspecify.annotations.Nullable;

import java.util.Collection;
import java.util.List;

/**
 * {@link ResponseHeaderPopulator} that adds the {@code Content-Security-Policy} header, or the
 * {@code Content-Security-Policy-Report-Only} header when report-only mode is enabled, to responses.
 * The header is only added to requests that {@link ContentSecurityPolicyFilter} matched, and not if
 * the response already contains it. With the default {@code /**} pattern, it is added to every
 * response, including one that a filter ordered before {@link ContentSecurityPolicyFilter} returned.
 *
 * <p>The bean is created at startup, so that a blank filter pattern fails application startup
 * instead of silently removing the policy.</p>
 *
 * @since 5.6.0
 */
@Context
@Internal
final class ContentSecurityPolicyResponseHeaderPopulator implements ResponseHeaderPopulator {
    private final ContentSecurityPolicyGenerator cspGenerator;
    private final ContentSecurityPolicyConfiguration cspConfiguration;
    private final boolean matchAll;

    /**
     * Creates the populator.
     *
     * @param cspGenerator generates the directives to write to the response
     * @param cspConfiguration configures how the policy is written
     * @param cspFilterConfiguration configures the request paths that receive the policy
     */
    ContentSecurityPolicyResponseHeaderPopulator(ContentSecurityPolicyGenerator cspGenerator,
                                                 ContentSecurityPolicyConfiguration cspConfiguration,
                                                 ContentSecurityPolicyFilterConfiguration cspFilterConfiguration) {
        this.cspGenerator = cspGenerator;
        this.cspConfiguration = cspConfiguration;
        String pattern = cspFilterConfiguration.getPattern();
        if (!StringUtils.hasText(pattern)) {
            // The filter resolves the same property through its @ServerFilter placeholder. A blank
            // pattern would match no request there, so the policy and nonce would silently
            // disappear. Fail startup instead, also when micronaut-validation is not available.
            throw new ConfigurationException(ContentSecurityPolicyFilterConfigurationProperties.PREFIX + ".pattern must not be blank");
        }
        this.matchAll = ServerFilter.MATCH_ALL_PATTERN.equals(pattern);
    }

    @Override
    public @Nullable Collection<HttpHeaderEntry> findHttpHeaders(HttpRequest<?> request, HttpResponse<?> response) {
        if (!matchAll && request.getAttribute(ContentSecurityPolicyFilter.MATCHED_ATTRIBUTE).isEmpty()) {
            return null;
        }
        if (cspGenerator instanceof DefaultContentSecurityPolicyGenerator defaultGenerator) {
            // The policy and its mode come from one configuration, also during a refresh.
            DefaultContentSecurityPolicyGenerator.GeneratedPolicy generated = defaultGenerator.generatePolicy(request);
            return header(generated.reportOnly(), generated.policy(), response);
        }
        boolean reportOnly = cspConfiguration.isReportOnly();
        if (response.getHeaders().contains(headerName(reportOnly))) {
            return null;
        }
        return header(reportOnly, cspGenerator.contentSecurityPolicy(request), response);
    }

    private static @Nullable Collection<HttpHeaderEntry> header(boolean reportOnly, @Nullable ContentSecurityPolicy csp, HttpResponse<?> response) {
        String headerName = headerName(reportOnly);
        if (csp == null || response.getHeaders().contains(headerName)) {
            return null;
        }
        return List.of(new HttpHeaderEntry(headerName, csp.toHeaderValue()));
    }

    private static String headerName(boolean reportOnly) {
        return reportOnly ? HttpHeaders.CONTENT_SECURITY_POLICY_REPORT_ONLY : HttpHeaders.CONTENT_SECURITY_POLICY;
    }
}
