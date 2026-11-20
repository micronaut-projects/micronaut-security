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
import java.util.StringJoiner;

import org.jspecify.annotations.Nullable;

/**
 * An ordered Content Security Policy that can be serialized to or parsed from an HTTP header.
 *
 * <p>The policy preserves the directive order from the header. Each directive has a name and an
 * optional value; value-less directives, such as {@code upgrade-insecure-requests}, are represented
 * with a {@code null} value. Directive lookups such as {@link #scriptSrc()} ignore the case of the
 * directive name and return the first of duplicate directives, as user agents do. This type parses the header for inspection; it does not validate CSP
 * directive names, source expressions, or the policy behavior implemented by a user agent.</p>
 *
 * @param directives the ordered directives in the policy
 * @since 5.6.0
 */
public record ContentSecurityPolicy(List<ContentSecurityPolicyDirective> directives) {
    private static final String DIRECTIVE_SEPARATOR = "; ";

    /**
     * Creates a policy with an immutable copy of the supplied directives.
     *
     * @param directives the ordered directives in the policy
     */
    public ContentSecurityPolicy {
        directives = List.copyOf(directives);
    }

    /**
     * Serializes this policy as a CSP header value.
     *
     * @return the semicolon-separated directives in their stored order
     * @since 5.6.0
     */
    public String toHeaderValue() {
        StringJoiner directives = new StringJoiner(DIRECTIVE_SEPARATOR);
        for (ContentSecurityPolicyDirective directive : directives()) {
            directives.add(directive.toHeaderValue());
        }
        return directives.toString();
    }

    /**
     * Describes this policy for logs and debuggers. Nonce source expressions are redacted because a
     * nonce is a secret of the response that carries it; use {@link #toHeaderValue()} to serialize
     * the policy.
     *
     * @return the semicolon-separated directives, with nonces redacted
     */
    @Override
    public String toString() {
        StringJoiner directives = new StringJoiner(DIRECTIVE_SEPARATOR);
        for (ContentSecurityPolicyDirective directive : directives()) {
            directives.add(directive.toString());
        }
        return directives.toString();
    }

    /**
     * Finds the {@code base-uri} directive.
     *
     * @return the {@code base-uri} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective baseUri() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.BASE_URI);
    }

    /**
     * Finds the {@code child-src} directive.
     *
     * @return the {@code child-src} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective childSrc() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.CHILD_SRC);
    }

    /**
     * Finds the {@code connect-src} directive.
     *
     * @return the {@code connect-src} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective connectSrc() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.CONNECT_SRC);
    }

    /**
     * Finds the {@code default-src} directive.
     *
     * @return the {@code default-src} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective defaultSrc() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.DEFAULT_SRC);
    }

    /**
     * Finds the {@code fenced-frame-src} directive.
     *
     * @return the {@code fenced-frame-src} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective fencedFrameSrc() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.FENCED_FRAME_SRC);
    }

    /**
     * Finds the {@code font-src} directive.
     *
     * @return the {@code font-src} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective fontSrc() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.FONT_SRC);
    }

    /**
     * Finds the {@code form-action} directive.
     *
     * @return the {@code form-action} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective formAction() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.FORM_ACTION);
    }

    /**
     * Finds the {@code frame-ancestors} directive.
     *
     * @return the {@code frame-ancestors} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective frameAncestors() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.FRAME_ANCESTORS);
    }

    /**
     * Finds the {@code frame-src} directive.
     *
     * @return the {@code frame-src} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective frameSrc() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.FRAME_SRC);
    }

    /**
     * Finds the {@code img-src} directive.
     *
     * @return the {@code img-src} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective imgSrc() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.IMG_SRC);
    }

    /**
     * Finds the {@code manifest-src} directive.
     *
     * @return the {@code manifest-src} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective manifestSrc() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.MANIFEST_SRC);
    }

    /**
     * Finds the {@code media-src} directive.
     *
     * @return the {@code media-src} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective mediaSrc() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.MEDIA_SRC);
    }

    /**
     * Finds the {@code object-src} directive.
     *
     * @return the {@code object-src} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective objectSrc() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.OBJECT_SRC);
    }

    /**
     * Finds the {@code prefetch-src} directive.
     *
     * @return the {@code prefetch-src} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective prefetchSrc() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.PREFETCH_SRC);
    }

    /**
     * Finds the {@code report-to} directive.
     *
     * @return the {@code report-to} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective reportTo() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.REPORT_TO);
    }

    /**
     * Finds the deprecated {@code report-uri} directive.
     *
     * @return the deprecated {@code report-uri} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective reportUri() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.REPORT_URI);
    }

    /**
     * Finds the {@code require-trusted-types-for} directive.
     *
     * @return the {@code require-trusted-types-for} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective requireTrustedTypesFor() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.REQUIRE_TRUSTED_TYPES_FOR);
    }

    /**
     * Finds the {@code sandbox} directive.
     *
     * @return the {@code sandbox} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective sandbox() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.SANDBOX);
    }

    /**
     * Finds the {@code script-src} directive.
     *
     * @return the {@code script-src} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective scriptSrc() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.SCRIPT_SRC);
    }

    /**
     * Finds the {@code script-src-attr} directive.
     *
     * @return the {@code script-src-attr} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective scriptSrcAttr() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.SCRIPT_SRC_ATTR);
    }

    /**
     * Finds the {@code script-src-elem} directive.
     *
     * @return the {@code script-src-elem} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective scriptSrcElem() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.SCRIPT_SRC_ELEM);
    }

    /**
     * Finds the {@code style-src} directive.
     *
     * @return the {@code style-src} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective styleSrc() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.STYLE_SRC);
    }

    /**
     * Finds the {@code style-src-attr} directive.
     *
     * @return the {@code style-src-attr} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective styleSrcAttr() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.STYLE_SRC_ATTR);
    }

    /**
     * Finds the {@code style-src-elem} directive.
     *
     * @return the {@code style-src-elem} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective styleSrcElem() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.STYLE_SRC_ELEM);
    }

    /**
     * Finds the {@code trusted-types} directive.
     *
     * @return the {@code trusted-types} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective trustedTypes() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.TRUSTED_TYPES);
    }

    /**
     * Finds the {@code upgrade-insecure-requests} directive.
     *
     * @return the {@code upgrade-insecure-requests} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective upgradeInsecureRequests() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.UPGRADE_INSECURE_REQUESTS);
    }

    /**
     * Finds the {@code worker-src} directive.
     *
     * @return the {@code worker-src} directive, or {@code null} if it is absent
     * @since 5.6.0
     */
    public @Nullable ContentSecurityPolicyDirective workerSrc() {
        return findByDirectiveName(ContentSecurityPolicyDirectiveNames.WORKER_SRC);
    }

    /**
     * Parses the enforcing Content Security Policy header from a response.
     *
     * @param response the HTTP response
     * @return the parsed policy from the first enforcing CSP header, or {@code null} if the response has none
     * @since 5.6.0
     */
    public static @Nullable ContentSecurityPolicy of(HttpResponse<?> response) {
        return of(response.getHeaders());
    }

    /**
     * Parses the enforcing Content Security Policy header from HTTP headers.
     *
     * @param headers the HTTP headers
     * @return the parsed policy, or {@code null} if the headers have no enforcing CSP header
     * @since 5.6.0
     */
    public static @Nullable ContentSecurityPolicy of(HttpHeaders headers) {
        return of(headers, HttpHeaders.CONTENT_SECURITY_POLICY);
    }

    /**
     * Parses a named Content Security Policy header from HTTP headers.
     *
     * <p>Use {@link HttpHeaders#CONTENT_SECURITY_POLICY_REPORT_ONLY} to parse a report-only policy.</p>
     *
     * <p>Only the first header with that name is parsed. A response can carry several CSP headers,
     * and a user agent enforces each of them as a separate policy; read them with
     * {@link HttpHeaders#getAll(CharSequence)} and parse each value with {@link #of(String)}.</p>
     *
     * @param headers the HTTP headers
     * @param headerName the CSP header name to parse
     * @return the parsed policy, or {@code null} if the named header is absent or empty
     * @since 5.6.0
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
     * <p>This parses a single policy. A header value that combines several policies with commas is
     * not split, and a user agent enforces each of those policies separately; do not use the result
     * to decide whether such a value is strict enough.</p>
     *
     * @param headerValue the serialized CSP header value
     * @return the parsed policy, or {@code null} if the value is {@code null} or empty
     * @since 5.6.0
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

    /**
     * Finds the first directive with the given name. Directive names are compared case-insensitively
     * and only the first of duplicate directives counts, as user agents do when parsing a policy.
     *
     * @param directiveName the lowercase directive name
     * @return the directive, or {@code null} if it is absent
     */
    private @Nullable ContentSecurityPolicyDirective findByDirectiveName(String directiveName) {
        return directives.stream()
                .filter(directive -> directive.name().equalsIgnoreCase(directiveName))
                .findFirst()
                .orElse(null);
    }
}
