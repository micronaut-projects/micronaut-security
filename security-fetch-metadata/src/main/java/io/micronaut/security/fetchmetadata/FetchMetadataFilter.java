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
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.SecFetch;
import io.micronaut.http.annotation.RequestFilter;
import io.micronaut.http.annotation.ResponseFilter;
import io.micronaut.http.annotation.ServerFilter;
import io.micronaut.http.filter.ServerFilterPhase;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Server filter that enforces the configured Fetch Metadata request-isolation policy.
 *
 * <p>It also adds {@code Sec-Fetch-Site}, {@code Sec-Fetch-Mode} and {@code Sec-Fetch-Dest} to
 * the {@code Vary} header of the responses to the requests it evaluates, both allowed and
 * rejected, because those responses depend on the Fetch Metadata request headers.</p>
 */
@Requires(property = FetchMetadataFilterConfiguration.PROPERTY_ENABLED, value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@ServerFilter("${" + FetchMetadataFilterConfiguration.PROPERTY_PATTERN + ":" + ServerFilter.MATCH_ALL_PATTERN + "}")
@Internal
public final class FetchMetadataFilter implements Ordered {
    private static final Logger LOG = LoggerFactory.getLogger(FetchMetadataFilter.class);
    private static final String GUIDE_URL = "https://micronaut-projects.github.io/micronaut-security/latest/guide/#fetchMetadata";
    private static final String ABSENT = "<absent>";
    private static final String UNRECOGNIZED = "<unrecognized>";
    private static final int MAX_LOGGED_LENGTH = 200;
    private static final List<String> VARY_HEADERS = List.of(
        HttpHeaders.SEC_FETCH_SITE,
        HttpHeaders.SEC_FETCH_MODE,
        HttpHeaders.SEC_FETCH_DEST);
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
    public HttpResponse<?> filterRequest(HttpRequest<?> request) {
        SecFetch secFetch = request.getSecFetch();
        if (secFetch != null) {
            // parsed once here, so that every HttpRequestFetchMetadataRule reuses it
            request.setAttribute(FetchMetadataAttributes.SEC_FETCH, secFetch);
        }
        for (FetchMetadataRule<HttpRequest<?>> rule : rules) {
            FetchMetadataRuleResult result = rule.check(request);
            if (result == FetchMetadataRuleResult.ALLOWED) {
                if (LOG.isTraceEnabled()) {
                    LOG.trace("request {} {} approved by rule {}", request.getMethod(), loggable(request.getPath()), rule.getClass().getSimpleName());
                }
                return null; // proceed
            } else if (result == FetchMetadataRuleResult.REJECTED) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("request {} {} rejected by rule {} ({}). See {}", request.getMethod(), loggable(request.getPath()),
                        rule.getClass().getSimpleName(), describeRequest(request, secFetch), GUIDE_URL);
                }
                return forbidden();
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("request {} {} rejected because no Fetch Metadata rule allowed it ({}). See {}",
                request.getMethod(), loggable(request.getPath()), describeRequest(request, secFetch), GUIDE_URL);
        }
        return forbidden();
    }

    /**
     * Adds the Fetch Metadata request headers to the {@code Vary} response header, so that a
     * shared cache does not serve a response allowed for one kind of request to another.
     *
     * @param response the response to decorate
     */
    @ResponseFilter
    public void filterResponse(MutableHttpResponse<?> response) {
        addVary(response);
    }

    private static void addVary(MutableHttpResponse<?> response) {
        List<String> vary = varyFields(response);
        if (vary.contains("*")) {
            return;
        }
        int existing = vary.size();
        for (String header : VARY_HEADERS) {
            if (vary.stream().noneMatch(header::equalsIgnoreCase)) {
                vary.add(header);
            }
        }
        if (vary.size() != existing) {
            response.getHeaders().set(HttpHeaders.VARY, String.join(", ", vary));
        }
    }

    /**
     * @param response the response
     * @return the distinct, case-insensitive field names of every {@code Vary} header of the response
     */
    private static List<String> varyFields(MutableHttpResponse<?> response) {
        List<String> fields = new ArrayList<>();
        for (String value : response.getHeaders().getAll(HttpHeaders.VARY)) {
            for (String field : value.split(",")) {
                String trimmed = field.trim();
                if (!trimmed.isEmpty() && fields.stream().noneMatch(trimmed::equalsIgnoreCase)) {
                    fields.add(trimmed);
                }
            }
        }
        return fields;
    }

    /**
     * Describes the request for a log message. Fetch Metadata values are logged as parsed, and the
     * free-form Origin header is truncated and stripped of control characters, so that a client
     * cannot write arbitrary text to the log.
     */
    private static String describeRequest(HttpRequest<?> request, @Nullable SecFetch secFetch) {
        HttpHeaders headers = request.getHeaders();
        String origin = headers.get(HttpHeaders.ORIGIN);
        return "site=" + parsedValue(headers, HttpHeaders.SEC_FETCH_SITE, secFetch != null ? secFetch.site() : null)
            + ", mode=" + parsedValue(headers, HttpHeaders.SEC_FETCH_MODE, secFetch != null ? secFetch.mode() : null)
            + ", dest=" + parsedValue(headers, HttpHeaders.SEC_FETCH_DEST, secFetch != null ? secFetch.dest() : null)
            + ", origin=" + (origin != null ? loggable(origin) : ABSENT)
            + ", cookie=" + (headers.contains(HttpHeaders.COOKIE) ? "present" : ABSENT);
    }

    private static String parsedValue(HttpHeaders headers, String name, @Nullable Object parsed) {
        if (parsed != null) {
            return parsed.toString();
        }
        return headers.contains(name) ? UNRECOGNIZED : ABSENT;
    }

    private static String loggable(String value) {
        String truncated = value.length() > MAX_LOGGED_LENGTH ? value.substring(0, MAX_LOGGED_LENGTH) + "..." : value;
        StringBuilder sb = new StringBuilder(truncated.length());
        for (int i = 0; i < truncated.length(); i++) {
            char c = truncated.charAt(i);
            sb.append(Character.isISOControl(c) ? '?' : c);
        }
        return sb.toString();
    }

    private static MutableHttpResponse<Object> forbidden() {
        // the response filter of this filter does not run for the response its request filter returns
        // no-store keeps a cache that ignores Vary from serving the rejection to other requests
        MutableHttpResponse<Object> response = HttpResponse.<Object>status(HttpStatus.FORBIDDEN)
            .header(HttpHeaders.CACHE_CONTROL, "no-store");
        addVary(response);
        return response;
    }
}
