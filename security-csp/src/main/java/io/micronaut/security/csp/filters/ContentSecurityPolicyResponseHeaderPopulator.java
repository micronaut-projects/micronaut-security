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
import io.micronaut.core.util.PathMatcher;
import io.micronaut.http.HttpHeaderEntry;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.server.filter.ResponseHeaderPopulator;
import io.micronaut.security.csp.ContentSecurityPolicy;
import io.micronaut.security.csp.ContentSecurityPolicyGenerator;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfiguration;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;

import java.util.Collection;
import java.util.List;

/**
 * {@link ResponseHeaderPopulator} that adds the {@code Content-Security-Policy} header, or the
 * {@code Content-Security-Policy-Report-Only} header when report-only mode is enabled, to responses.
 * The header is only added to requests whose path matches the configured filter pattern, and not
 * if the response already contains it.
 *
 * @since 5.4.0
 */
@Requires(classes = ResponseHeaderPopulator.class)
@Singleton
@Internal
final class ContentSecurityPolicyResponseHeaderPopulator implements ResponseHeaderPopulator {
    private final ContentSecurityPolicyGenerator cspGenerator;
    private final ContentSecurityPolicyConfiguration cspConfiguration;
    private final ContentSecurityPolicyFilterConfiguration cspFilterConfiguration;

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
        this.cspFilterConfiguration = cspFilterConfiguration;
    }

    @Override
    public @Nullable Collection<HttpHeaderEntry> findHttpHeaders(HttpRequest<?> request, HttpResponse<?> response) {
        if (!PathMatcher.ANT.matches(cspFilterConfiguration.getPattern(), request.getPath())) {
            return null;
        }
        String headerName = cspConfiguration.isReportOnly()
            ? ContentSecurityPolicy.CONTENT_SECURITY_POLICY_REPORT_ONLY : ContentSecurityPolicy.CONTENT_SECURITY_POLICY;
        boolean responseSetsAlreadyCspHeader = response.getHeaders().contains(headerName);
        if (!responseSetsAlreadyCspHeader) {
            ContentSecurityPolicy csp = cspGenerator.contentSecurityPolicy(request);
            if (csp != null) {
                return List.of(new HttpHeaderEntry(headerName, csp.toString()));
            }
        }
        return null;
    }
}
