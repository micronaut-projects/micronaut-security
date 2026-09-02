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
package io.micronaut.security.fetchmetadata;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.order.Ordered;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.SecFetch;
import io.micronaut.http.annotation.RequestFilter;
import io.micronaut.http.annotation.ServerFilter;
import io.micronaut.http.filter.ServerFilterPhase;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Server filter that enforces the configured Fetch Metadata request-isolation policy.
 */
@Requires(property = FetchMetadataFilterConfigurationProperties.PROPERTY_ENABLED, value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@Requires(classes = ServerFilter.class)
@ServerFilter("${" + FetchMetadataFilterConfigurationProperties.PREFIX + ".pattern:" + ServerFilter.MATCH_ALL_PATTERN + "}")
@Internal
public final class FetchMetadataFilter implements Ordered {
    private static final Logger LOG = LoggerFactory.getLogger(FetchMetadataFilter.class);
    private final List<FetchMetadataRule<HttpRequest<?>>> rules;

    /**
     * @param rules Fetch Metadata rules, in evaluation order
     */
    FetchMetadataFilter(List<FetchMetadataRule<HttpRequest<?>>> rules) {
        this.rules = List.copyOf(rules);
    }

    /**
     * Runs Fetch Metadata isolation before authentication and authorization filters.
     *
     * @return an order before the main security filter
     */
    @Override
    public int getOrder() {
        return ServerFilterPhase.SECURITY.before();
    }

    /**
     * Evaluates the request against the configured Fetch Metadata rules.
     *
     * <p>The first rule that returns {@link FetchMetadataRuleResult#ALLOWED} or
     * {@link FetchMetadataRuleResult#REJECTED} decides the result. The filter denies the request
     * when every rule returns {@link FetchMetadataRuleResult#UNKNOWN}.</p>
     *
     * @param request the request to evaluate
     * @return {@code null} to continue processing, or a forbidden response to reject the request
     */
    @RequestFilter
    @Nullable
    @Internal
    public HttpResponse<?> filterRequest(HttpRequest<?> request) {
        for (FetchMetadataRule<HttpRequest<?>> rule : rules) {
            FetchMetadataRuleResult result = rule.check(request);
            if (result == FetchMetadataRuleResult.ALLOWED) {
                if (LOG.isTraceEnabled()) {
                    LOG.trace("request {} {} approved by rule {}", request.getMethod(), request.getPath(), rule.getClass().getSimpleName());
                }
                return null; // proceed

            } else if (result == FetchMetadataRuleResult.REJECTED) {
                if (LOG.isTraceEnabled()) {
                    LOG.trace("request {} {} rejected by rule {}", request.getMethod(), request.getPath(), rule.getClass().getSimpleName());
                }
                return forbidden();
            }
        }
        if (LOG.isDebugEnabled()) {
            SecFetch secFetch = request.getSecFetch();
            String destination = secFetch != null ? secFetch.dest().toString() : "";
            String mode = secFetch != null ? secFetch.mode().toString() : "";
            String site = secFetch != null ? secFetch.site().toString() : "";
            LOG.debug("request {} {} rejected because no Fetch Metadata rule allowed it. Fetch Metadata(dest: {}, mode: {}, site: {})",
                request.getMethod(),
                request.getPath(),
                destination,
                mode,
                site);
        }
        return forbidden();
    }

    private static MutableHttpResponse<Object> forbidden() {
        return HttpResponse.status(HttpStatus.FORBIDDEN);
    }
}
