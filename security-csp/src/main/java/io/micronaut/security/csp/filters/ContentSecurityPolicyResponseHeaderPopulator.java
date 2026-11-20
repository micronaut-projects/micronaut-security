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
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.PathMatcher;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpHeaderEntry;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.ServerFilter;
import io.micronaut.http.context.ServerContextPathProvider;
import io.micronaut.http.server.filter.ResponseHeaderPopulator;
import io.micronaut.security.csp.ContentSecurityPolicy;
import io.micronaut.security.csp.ContentSecurityPolicyGenerator;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfiguration;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;

/**
 * {@link ResponseHeaderPopulator} that adds the {@code Content-Security-Policy} header, or the
 * {@code Content-Security-Policy-Report-Only} header when report-only mode is enabled, to responses.
 * The header is only added to requests whose path matches the configured filter pattern the way
 * Micronaut Core matches the pattern of the nonce filter, and not if the response already contains it.
 *
 * @since 5.6.0
 */
@Requires(classes = ResponseHeaderPopulator.class)
@Singleton
@Internal
final class ContentSecurityPolicyResponseHeaderPopulator implements ResponseHeaderPopulator {
    private static final String SLASH = "/";
    private final ContentSecurityPolicyGenerator cspGenerator;
    private final ContentSecurityPolicyConfiguration cspConfiguration;
    private final boolean matchAll;
    /**
     * The pattern when it is matched against the whole request path, or {@code null} when it is
     * relative to the context path.
     */
    private final @Nullable String absolutePattern;
    /**
     * The pattern when it is relative to the context path, or {@code null}.
     */
    private final @Nullable String contextPathPattern;
    /**
     * The normalized context path, without a trailing slash, or {@code null} when there is none.
     */
    private final @Nullable String contextPath;

    /**
     * Creates the populator.
     *
     * @param cspGenerator generates the directives to write to the response
     * @param cspConfiguration configures how the policy is written
     * @param cspFilterConfiguration configures the request paths that receive the policy
     * @param serverContextPathProvider supplies the server context path, if any
     */
    ContentSecurityPolicyResponseHeaderPopulator(ContentSecurityPolicyGenerator cspGenerator,
                                                 ContentSecurityPolicyConfiguration cspConfiguration,
                                                 ContentSecurityPolicyFilterConfiguration cspFilterConfiguration,
                                                 @Nullable ServerContextPathProvider serverContextPathProvider) {
        this.cspGenerator = cspGenerator;
        this.cspConfiguration = cspConfiguration;
        String pattern = cspFilterConfiguration.getPattern();
        if (!StringUtils.hasText(pattern)) {
            // The nonce filter resolves the same property through its @ServerFilter placeholder. A
            // blank pattern would match no request there, so the policy and nonce would silently
            // disappear. Fail startup instead, also when micronaut-validation is not available.
            throw new ConfigurationException(ContentSecurityPolicyFilterConfigurationProperties.PREFIX + ".pattern must not be blank");
        }
        this.matchAll = ServerFilter.MATCH_ALL_PATTERN.equals(pattern);
        this.contextPath = normalize(serverContextPathProvider == null ? null : serverContextPathProvider.getContextPath());
        if (contextPath == null || isUnderContextPath(contextPath, pattern)) {
            this.absolutePattern = pattern;
            this.contextPathPattern = null;
        } else {
            this.absolutePattern = null;
            this.contextPathPattern = pattern.startsWith(SLASH) ? pattern : SLASH + pattern;
        }
    }

    /**
     * Normalizes the context path the way the server does for filter patterns: with a leading slash
     * and without trailing slashes.
     *
     * @param contextPath the server context path, if any
     * @return the normalized context path, or {@code null} when there is none
     */
    private static @Nullable String normalize(@Nullable String contextPath) {
        if (contextPath == null) {
            return null;
        }
        String normalized = contextPath.startsWith(SLASH) ? contextPath : SLASH + contextPath;
        while (normalized.endsWith(SLASH)) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized.isEmpty() ? null : normalized;
    }

    private static boolean isUnderContextPath(String contextPath, String path) {
        return path.startsWith(contextPath) && (path.length() == contextPath.length() || path.charAt(contextPath.length()) == '/');
    }

    @Override
    public @Nullable Collection<HttpHeaderEntry> findHttpHeaders(HttpRequest<?> request, HttpResponse<?> response) {
        if (!matchAll && !matches(request.getPath())) {
            return null;
        }
        String headerName = cspConfiguration.isReportOnly()
            ? HttpHeaders.CONTENT_SECURITY_POLICY_REPORT_ONLY : HttpHeaders.CONTENT_SECURITY_POLICY;
        boolean responseSetsAlreadyCspHeader = response.getHeaders().contains(headerName);
        if (!responseSetsAlreadyCspHeader) {
            ContentSecurityPolicy csp = cspGenerator.contentSecurityPolicy(request);
            if (csp != null) {
                return List.of(new HttpHeaderEntry(headerName, csp.toHeaderValue()));
            }
        }
        return null;
    }

    /**
     * Matches the request path the way Micronaut Core matches the {@code @ServerFilter} pattern of
     * the nonce filter, so that the header is written exactly for the requests that receive a nonce.
     * A pattern that does not start with the context path is relative to it: it is matched against
     * the part of the path after the context path, and against the whole path of a request outside
     * the context path.
     *
     * @param path the raw request path
     * @return whether the request receives the policy
     */
    private boolean matches(String path) {
        if (absolutePattern != null) {
            return matchesAnyForm(absolutePattern, path);
        }
        String relativePath = path;
        if (contextPath != null && isUnderContextPath(contextPath, path)) {
            relativePath = path.length() == contextPath.length() ? SLASH : path.substring(contextPath.length());
        }
        return contextPathPattern != null && matchesAnyForm(contextPathPattern, relativePath);
    }

    /**
     * Matches a pattern against the raw path and the forms of it that the server also matches filter
     * patterns against: the path without its trailing slash, and the percent-decoded path with and
     * without its trailing slash.
     *
     * @param pattern the Ant-style pattern
     * @param path the raw request path
     * @return whether any form of the path matches
     */
    static boolean matchesAnyForm(String pattern, String path) {
        if (PathMatcher.ANT.matches(pattern, path)) {
            return true;
        }
        if (path.isEmpty()) {
            return PathMatcher.ANT.matches(pattern, SLASH);
        }
        String stripped = trimTrailingSlash(path);
        if (stripped != null && PathMatcher.ANT.matches(pattern, stripped)) {
            return true;
        }
        if (path.indexOf('%') == -1) {
            return false;
        }
        String decoded;
        try {
            decoded = URLDecoder.decode(path.replace("+", "%2B"), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (PathMatcher.ANT.matches(pattern, decoded)) {
            return true;
        }
        String decodedStripped = trimTrailingSlash(decoded);
        return decodedStripped != null && PathMatcher.ANT.matches(pattern, decodedStripped);
    }

    private static @Nullable String trimTrailingSlash(String path) {
        int length = path.length();
        return length > 1 && path.charAt(length - 1) == '/' ? path.substring(0, length - 1) : null;
    }
}
