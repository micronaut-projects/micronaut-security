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
 * with a {@code null} value.</p>
 *
 * @param directives the ordered directives in the policy
 * @since 5.4.0
 */
public record ContentSecurityPolicy(List<CspDirective> directives) {
    /**
     * @return the {@code base-uri} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective baseUri() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.BASE_URI);
    }

    /**
     * @return the {@code child-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective childSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.CHILD_SRC);
    }

    /**
     * @return the {@code connect-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective connectSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.CONNECT_SRC);
    }

    /**
     * @return the {@code default-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective defaultSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.DEFAULT_SRC);
    }

    /**
     * @return the {@code fenced-frame-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective fencedFrameSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.FENCED_FRAME_SRC);
    }

    /**
     * @return the {@code font-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective fontSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.FONT_SRC);
    }

    /**
     * @return the {@code form-action} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective formAction() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.FORM_ACTION);
    }

    /**
     * @return the {@code frame-ancestors} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective frameAncestors() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.FRAME_ANCESTORS);
    }

    /**
     * @return the {@code frame-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective frameSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.FRAME_SRC);
    }

    /**
     * @return the {@code img-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective imgSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.IMG_SRC);
    }

    /**
     * @return the {@code manifest-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective manifestSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.MANIFEST_SRC);
    }

    /**
     * @return the {@code media-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective mediaSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.MEDIA_SRC);
    }

    /**
     * @return the {@code object-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective objectSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.OBJECT_SRC);
    }

    /**
     * @return the {@code prefetch-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective prefetchSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.PREFETCH_SRC);
    }

    /**
     * @return the {@code report-to} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective reportTo() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.REPORT_TO);
    }

    /**
     * @return the deprecated {@code report-uri} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective reportUri() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.REPORT_URI);
    }

    /**
     * @return the {@code require-trusted-types-for} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective requireTrustedTypesFor() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.REQUIRE_TRUSTED_TYPES_FOR);
    }

    /**
     * @return the {@code sandbox} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective sandbox() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.SANDBOX);
    }

    /**
     * @return the {@code script-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective scriptSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.SCRIPT_SRC);
    }

    /**
     * @return the {@code script-src-attr} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective scriptSrcAttr() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.SCRIPT_SRC_ATTR);
    }

    /**
     * @return the {@code script-src-elem} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective scriptSrcElem() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.SCRIPT_SRC_ELEM);
    }

    /**
     * @return the {@code style-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective styleSrc() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.STYLE_SRC);
    }

    /**
     * @return the {@code style-src-attr} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective styleSrcAttr() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.STYLE_SRC_ATTR);
    }

    /**
     * @return the {@code style-src-elem} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective styleSrcElem() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.STYLE_SRC_ELEM);
    }

    /**
     * @return the {@code trusted-types} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective trustedTypes() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.TRUSTED_TYPES);
    }

    /**
     * @return the {@code upgrade-insecure-requests} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective upgradeInsecureRequests() {
        return findByDirectiveName(ContentSecurityPolicyGenerator.UPGRADE_INSECURE_REQUESTS);
    }

    /**
     * @return the {@code worker-src} directive, or {@code null} if it is absent
     * @since 5.4.0
     */
    public @Nullable CspDirective workerSrc() {
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
        return of(headers, CspHeaders.CONTENT_SECURITY_POLICY);
    }

    /**
     * Parses a named Content Security Policy header from HTTP headers.
     *
     * <p>Use {@link CspHeaders#CONTENT_SECURITY_POLICY_REPORT_ONLY} to parse a report-only policy.</p>
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
     * preserved.</p>
     *
     * @param headerValue the serialized CSP header value
     * @return the parsed policy, or {@code null} if the value is {@code null} or empty
     */
    public static @Nullable ContentSecurityPolicy of(@Nullable String headerValue) {
        if (StringUtils.isEmpty(headerValue)) {
            return null;
        }
        List<CspDirective> directives = List.of(headerValue.split(";", -1)).stream()
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
    private static CspDirective directive(String component) {
        String[] parts = component.split("\\s+", 2);
        return new CspDirective(parts[0], parts.length == 1 ? null : parts[1]);
    }

    private @Nullable CspDirective findByDirectiveName(String directiveName) {
        return directives.stream()
                .filter(directive -> directive.name().equals(directiveName))
                .findFirst()
                .orElse(null);
    }
}
