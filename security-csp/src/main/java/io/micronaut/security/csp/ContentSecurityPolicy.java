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

import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpResponse;

import java.util.List;

import org.jspecify.annotations.Nullable;

/**
 * A parsed Content Security Policy response header.
 *
 * <p>The policy preserves the directive order from the header. Each directive has a name and an
 * optional value; value-less directives, such as {@code upgrade-insecure-requests}, are represented
 * with a {@code null} value. This type parses the header for inspection; it does not validate CSP
 * directive names, source expressions, or the policy behavior implemented by a user agent.</p>
 *
 * @param directives the ordered directives in the policy
 * @since 5.4.0
 */
public record ContentSecurityPolicy(List<ContentSecurityPolicyDirective> directives) {
    /**
     * Header that causes user agents to enforce the supplied policy.
     *
     * @since 5.4.0
     */
    public static final String CONTENT_SECURITY_POLICY = "Content-Security-Policy";
    /**
     * Header that reports policy violations without enforcing the supplied policy.
     *
     * @since 5.4.0
     */
    public static final String CONTENT_SECURITY_POLICY_REPORT_ONLY = "Content-Security-Policy-Report-Only";

    /**
     * @return the {@code base-uri} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective baseUri() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.BASE_URI);
    }

    /**
     * @return the {@code child-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective childSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.CHILD_SRC);
    }

    /**
     * @return the {@code connect-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective connectSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.CONNECT_SRC);
    }

    /**
     * @return the {@code default-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective defaultSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.DEFAULT_SRC);
    }

    /**
     * @return the {@code fenced-frame-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective fencedFrameSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.FENCED_FRAME_SRC);
    }

    /**
     * @return the {@code font-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective fontSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.FONT_SRC);
    }

    /**
     * @return the {@code form-action} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective formAction() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.FORM_ACTION);
    }

    /**
     * @return the {@code frame-ancestors} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective frameAncestors() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.FRAME_ANCESTORS);
    }

    /**
     * @return the {@code frame-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective frameSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.FRAME_SRC);
    }

    /**
     * @return the {@code img-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective imgSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.IMG_SRC);
    }

    /**
     * @return the {@code manifest-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective manifestSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.MANIFEST_SRC);
    }

    /**
     * @return the {@code media-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective mediaSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.MEDIA_SRC);
    }

    /**
     * @return the {@code object-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective objectSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.OBJECT_SRC);
    }

    /**
     * @return the {@code prefetch-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective prefetchSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.PREFETCH_SRC);
    }

    /**
     * @return the {@code report-to} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective reportTo() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.REPORT_TO);
    }

    /**
     * @return the deprecated {@code report-uri} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective reportUri() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.REPORT_URI);
    }

    /**
     * @return the {@code require-trusted-types-for} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective requireTrustedTypesFor() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.REQUIRE_TRUSTED_TYPES_FOR);
    }

    /**
     * @return the {@code sandbox} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective sandbox() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.SANDBOX);
    }

    /**
     * @return the {@code script-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective scriptSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.SCRIPT_SRC);
    }

    /**
     * @return the {@code script-src-attr} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective scriptSrcAttr() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.SCRIPT_SRC_ATTR);
    }

    /**
     * @return the {@code script-src-elem} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective scriptSrcElem() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.SCRIPT_SRC_ELEM);
    }

    /**
     * @return the {@code style-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective styleSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.STYLE_SRC);
    }

    /**
     * @return the {@code style-src-attr} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective styleSrcAttr() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.STYLE_SRC_ATTR);
    }

    /**
     * @return the {@code style-src-elem} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective styleSrcElem() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.STYLE_SRC_ELEM);
    }

    /**
     * @return the {@code trusted-types} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective trustedTypes() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.TRUSTED_TYPES);
    }

    /**
     * @return the {@code upgrade-insecure-requests} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective upgradeInsecureRequests() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.UPGRADE_INSECURE_REQUESTS);
    }

    /**
     * @return the {@code worker-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable ContentSecurityPolicyDirective workerSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.WORKER_SRC);
    }

    /**
     * Parses the enforcing Content Security Policy header from a response.
     *
     * @param response the HTTP response
     * @return the parsed policy, or {@code null} if the response has no enforcing CSP header
     */
    public static @Nullable ContentSecurityPolicy of(HttpResponse<?> response) {
        return of(response.getHeaders());
    }

    /**
     * Parses the enforcing Content Security Policy header from HTTP headers.
     *
     * @param headers the HTTP headers
     * @return the parsed policy, or {@code null} if the headers have no enforcing CSP header
     */
    public static @Nullable ContentSecurityPolicy of(HttpHeaders headers) {
        return of(headers, ContentSecurityPolicy.CONTENT_SECURITY_POLICY);
    }

    /**
     * Parses a named Content Security Policy header from HTTP headers.
     *
     * <p>Use {@link ContentSecurityPolicy#CONTENT_SECURITY_POLICY_REPORT_ONLY} to parse a report-only policy.</p>
     *
     * @param headers the HTTP headers
     * @param headerName the CSP header name to parse
     * @return the parsed policy, or {@code null} if the named header is absent or empty
     */
    public static @Nullable ContentSecurityPolicy of(HttpHeaders headers, String headerName) {
        return of(headers.get(headerName));
    }

    /**
     * Parses a serialized Content Security Policy header value.
     *
     * <p>Empty directive components, such as those introduced by consecutive semicolons, are ignored.
     * Whitespace between a directive name and its value is normalized, but a directive value is otherwise
     * preserved. The parser deliberately does not reject unknown or malformed directives so callers can
     * inspect the header as it was received.</p>
     *
     * @param headerValue the serialized CSP header value
     * @return the parsed policy, or {@code null} if the value is {@code null} or empty
     */
    public static @Nullable ContentSecurityPolicy of(@Nullable String headerValue) {
        if (StringUtils.isEmpty(headerValue)) {
            return null;
        }
        List<ContentSecurityPolicyDirective> directives = List.of(headerValue.split(";", -1)).stream()
                .map(String::trim)
                .filter(StringUtils::isNotEmpty)
                .map(ContentSecurityPolicy::directive)
                .toList();
        return new ContentSecurityPolicy(directives);
    }

    /**
     * Parses a non-empty directive component into its name and optional value.
     *
     * @param component the trimmed component from the CSP header
     * @return the parsed directive
     */
    private static ContentSecurityPolicyDirective directive(String component) {
        String[] parts = component.split("\\s+", 2);
        return new ContentSecurityPolicyDirective(parts[0], parts.length == 1 ? null : parts[1]);
    }

    private @Nullable ContentSecurityPolicyDirective findByDirectiveName(String directiveName) {
        return directives.stream()
                .filter(directive -> directive.name().equals(directiveName))
                .findFirst()
                .orElse(null);
    }
}
