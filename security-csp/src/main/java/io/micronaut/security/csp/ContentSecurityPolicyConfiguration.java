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

import io.micronaut.core.util.Toggleable;

import java.util.List;

/**
 * Configuration for Content Security Policy response headers.
 *
 * <p>Each directive can be disabled independently. Source-list directive values are represented as
 * individual CSP source expressions and are serialized as a space-separated list in the response header.
 * Implementations should return values in the exact form expected by the CSP header, including quotes
 * around CSP keywords such as {@code 'self'} and {@code 'none'}.</p>
 *
 * <p>URL-based CSP policies are ineffective as a primary defense against cross-site scripting because
 * an allowlisted origin can contain attacker-controlled or exploitable content. Prefer nonce- or
 * hash-based {@code script-src} policies, optionally combined with {@code 'strict-dynamic'}, over
 * URL source expressions. Configure script URLs only when required for compatibility.</p>
 *
 * @since 5.4.0
 */
public interface ContentSecurityPolicyConfiguration extends Toggleable {
    /**
     * @return whether to report policy violations without enforcing the policy
     */
    boolean isReportOnly();

    /**
     * @return whether to prevent a document from changing how its relative URLs resolve
     */
    boolean isBaseUriEnabled();

    /**
     * @return the allowed sources for a document's {@code base} element
     */
    List<String> getBaseUri();

    /**
     * @return whether to use a fallback policy for fetch directives that are not explicitly configured
     * @since 5.4.0
     */
    boolean isDefaultSrcEnabled();

    /**
     * @return the fallback source expressions for fetch directives that are not explicitly configured
     * @since 5.4.0
     */
    List<String> getDefaultSrc();

    /**
     * @return whether to restrict the endpoints scripts may connect to
     */
    boolean isConnectSrcEnabled();

    /**
     * @return the allowed endpoints for {@code fetch}, {@code XMLHttpRequest}, WebSocket, EventSource,
     * and similar script-initiated connections
     */
    List<String> getConnectSrc();

    /**
     * @return whether to restrict documents loaded in {@code fencedframe} elements
     * @since 5.4.0
     */
    boolean isFencedFrameSrcEnabled();

    /**
     * @return the allowed sources for fenced frame documents
     * @since 5.4.0
     */
    List<String> getFencedFrameSrc();

    /**
     * @return whether to restrict where the document may load fonts from
     */
    boolean isFontSrcEnabled();

    /**
     * @return the allowed sources for fonts loaded through {@code @font-face}
     */
    List<String> getFontSrc();

    /**
     * @return whether to restrict legacy plugin content
     */
    boolean isObjectSrcEnabled();

    /**
     * @return the allowed sources for content loaded by {@code object} and {@code embed} elements
     */
    List<String> getObjectSrc();

    /**
     * @return whether to restrict resources fetched speculatively by prefetching and prerendering
     */
    boolean isPrefetchSrcEnabled();

    /**
     * @return the allowed sources for speculative resource requests
     */
    List<String> getPrefetchSrc();

    /**
     * @return whether to send CSP violation reports to the configured legacy reporting endpoints
     * @since 5.4.0
     */
    boolean isReportUriEnabled();

    /**
     * @return the reporting endpoint URLs for the deprecated {@code report-uri} directive
     * @since 5.4.0
     */
    List<String> getReportUri();

    /**
     * @return whether to require Trusted Types for selected DOM injection sinks
     */
    boolean isRequireTrustedTypesForEnabled();

    /**
     * @return the Trusted Types sink group, such as {@code 'script'}, to enforce
     */
    String getRequireTrustedTypesFor();

    /**
     * @return whether to restrict which origins may embed the document, protecting against clickjacking
     */
    boolean isFrameAncestorsEnabled();

    /**
     * @return the origins allowed to embed the document in a frame
     */
    List<String> getFrameAncestors();

    /**
     * @return whether to restrict documents loaded in {@code frame} and {@code iframe} elements
     */
    boolean isFrameSrcEnabled();

    /**
     * @return the allowed sources for nested browsing contexts
     */
    List<String> getFrameSrc();

    /**
     * @return whether to restrict images and favicons loaded by the document
     */
    boolean isImgSrcEnabled();

    /**
     * @return the allowed sources for image and favicon resources
     */
    List<String> getImgSrc();

    /**
     * @return whether to restrict web application manifest files
     */
    boolean isManifestSrcEnabled();

    /**
     * @return the allowed sources for web application manifest files
     */
    List<String> getManifestSrc();

    /**
     * @return whether to restrict media loaded by the document
     */
    boolean isMediaSrcEnabled();

    /**
     * @return the allowed sources for {@code audio}, {@code video}, and {@code track} resources
     */
    List<String> getMediaSrc();

    /**
     * @return whether to restrict where forms may submit data
     */
    boolean isFormActionEnabled();

    /**
     * @return the allowed form submission endpoints
     */
    List<String> getFormAction();

    /**
     * @return whether to add a per-response nonce to {@code script-src}, allowing only matching scripts
     */
    boolean isScriptSrcNonceEnabled();

    /**
     * @return whether {@code 'strict-dynamic'} is added to the {@code script-src} directive.
     * When enabled, a script trusted via the nonce may load further scripts regardless of any
     * source expression, which lets libraries that re-insert {@code <script>} elements at
     * runtime (e.g. Turbo Drive) keep working under a nonce-based policy.
     * @see <a href="https://content-security-policy.com/strict-dynamic/">strict-dynamic</a>
     */
    boolean isScriptSrcStrictDynamic();

    /**
     * @return whether to add {@code 'self'} to {@code script-src}, permitting scripts from the application's origin
     */
    boolean isScriptSrcSelf();

    /**
     * @return CSP hash source expressions to add to {@code script-src}, without requiring a per-request nonce
     */
    List<String> getScriptSrcHashes();

    /**
     * @return URL source expressions to add to {@code script-src}, allowing scripts from those locations;
     * URL allowlists are ineffective as a primary XSS defense and should be used only for compatibility
     */
    List<String> getScriptSrcUrls();

    /**
     * @return whether to add {@code 'unsafe-inline'} to {@code script-src}, permitting inline scripts
     * that do not carry an allowed nonce or hash
     */
    boolean isScriptSrcUnsafeInline();

    /**
     * @return whether to add {@code 'unsafe-eval'} to {@code script-src}, permitting JavaScript
     * string-to-code APIs such as {@code eval}
     */
    boolean isScriptSrcUnsafeEval();

    /**
     * @return whether to add the unquoted {@code http:} scheme source to {@code script-src}; this permits
     * scripts from any HTTP origin and is therefore insecure
     */
    boolean isScriptSrcHttp();

    /**
     * @return whether to add the unquoted {@code https:} scheme source to {@code script-src}, permitting
     * scripts from any HTTPS origin
     */
    boolean isScriptSrcHttps();

    /**
     * @return whether to restrict stylesheets and inline style blocks
     */
    boolean isStyleSrcEnabled();

    /**
     * @return the allowed sources for stylesheet and style resources
     */
    List<String> getStyleSrc();

    /**
     * @return whether to restrict scripts loaded by web workers
     */
    boolean isWorkerSrcEnabled();

    /**
     * @return the allowed sources for worker scripts
     */
    List<String> getWorkerSrc();
}
