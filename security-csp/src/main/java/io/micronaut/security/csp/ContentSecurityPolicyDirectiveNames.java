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

/**
 * Names of standard Content Security Policy directives.
 *
 * <p>A directive explicitly present in a policy takes precedence over {@link #DEFAULT_SRC};
 * {@code default-src} is a fallback, not a value inherited by every directive.</p>
 *
 * @see <a href="https://www.w3.org/TR/CSP3/#csp-directives">CSP directives</a>
 * @since 5.6.0
 */
public final class ContentSecurityPolicyDirectiveNames {
    /**
     * The {@code base-uri} directive, which restricts the URLs that a document's {@code base} element
     * may use. This prevents injected markup from changing how relative URLs resolve.
     */
    public static final String BASE_URI = "base-uri";

    /**
     * The {@code child-src} directive, which restricts nested browsing contexts and worker scripts.
     * It is retained as a fallback for {@code frame-src} and {@code worker-src} in browsers that
     * support it; prefer the more specific directives for new policies.
     */
    public static final String CHILD_SRC = "child-src";

    /**
     * The {@code connect-src} directive, which restricts URLs used by script interfaces such as
     * {@code fetch}, {@code XMLHttpRequest}, WebSocket, and EventSource.
     */
    public static final String CONNECT_SRC = "connect-src";

    /**
     * The {@code default-src} directive, which supplies a fallback source list only for fetch
     * directives that are absent. It does not constrain a directive that is explicitly present.
     */
    public static final String DEFAULT_SRC = "default-src";

    /**
     * The {@code fenced-frame-src} directive, which restricts documents loaded by
     * {@code fencedframe} elements.
     */
    public static final String FENCED_FRAME_SRC = "fenced-frame-src";

    /**
     * The {@code font-src} directive, which restricts fonts loaded through {@code @font-face}.
     */
    public static final String FONT_SRC = "font-src";

    /**
     * The {@code form-action} directive, which restricts the URLs to which a document may submit forms.
     * This prevents a compromised page from submitting form data to an untrusted origin.
     */
    public static final String FORM_ACTION = "form-action";

    /**
     * The {@code frame-ancestors} directive, which restricts the origins allowed to embed the document.
     * This helps protect the application from clickjacking.
     */
    public static final String FRAME_ANCESTORS = "frame-ancestors";

    /**
     * The {@code frame-src} directive, which restricts documents loaded by {@code frame} and
     * {@code iframe} elements. Disabling nested documents reduces the risk of rendering untrusted content.
     */
    public static final String FRAME_SRC = "frame-src";

    /**
     * The {@code img-src} directive, which restricts images and favicons. It can prevent injected
     * markup from making unexpected requests through image loads.
     */
    public static final String IMG_SRC = "img-src";

    /**
     * The {@code manifest-src} directive, which restricts web application manifest files.
     */
    public static final String MANIFEST_SRC = "manifest-src";

    /**
     * The {@code media-src} directive, which restricts media loaded by {@code audio}, {@code video},
     * and {@code track} elements.
     */
    public static final String MEDIA_SRC = "media-src";

    /**
     * The {@code object-src} directive, which restricts plugin content loaded by {@code object} and
     * {@code embed} elements. Disabling this legacy content reduces an application's attack surface.
     */
    public static final String OBJECT_SRC = "object-src";

    /**
     * The {@code prefetch-src} directive, which restricts resources fetched speculatively through
     * prefetching or prerendering.
     */
    public static final String PREFETCH_SRC = "prefetch-src";

    /**
     * The {@code report-to} directive, which selects a Reporting API endpoint group to receive CSP
     * violation reports. Reporting must also be configured through the Reporting API response header.
     */
    public static final String REPORT_TO = "report-to";

    /**
     * The deprecated {@code report-uri} directive, which lists endpoints that receive CSP
     * violation reports. Use it together with {@link #REPORT_TO} when supporting browsers that do
     * not implement the Reporting API.
     */
    public static final String REPORT_URI = "report-uri";

    /**
     * The {@code require-trusted-types-for} directive, which requires Trusted Types at selected DOM
     * injection sinks and can reduce client-side XSS risk.
     */
    public static final String REQUIRE_TRUSTED_TYPES_FOR = "require-trusted-types-for";

    /**
     * The {@code sandbox} directive, which applies sandbox restrictions to the document in a similar
     * way to the {@code sandbox} attribute on an {@code iframe}. Its value consists of optional
     * sandbox permissions; omitting them applies the strictest sandbox.
     */
    public static final String SANDBOX = "sandbox";

    /**
     * The {@code script-src} directive, which restricts JavaScript and WebAssembly resources. It is a
     * primary defense-in-depth control against cross-site scripting. A nonce or hash permits only
     * matching inline scripts without enabling all inline script execution.
     */
    public static final String SCRIPT_SRC = "script-src";

    /**
     * The {@code script-src-attr} directive, which restricts inline JavaScript event-handler attributes.
     */
    public static final String SCRIPT_SRC_ATTR = "script-src-attr";

    /**
     * The {@code script-src-elem} directive, which restricts JavaScript loaded by {@code script}
     * elements.
     */
    public static final String SCRIPT_SRC_ELEM = "script-src-elem";

    /**
     * The {@code style-src} directive, which restricts stylesheets and inline style blocks.
     */
    public static final String STYLE_SRC = "style-src";

    /**
     * The {@code style-src-attr} directive, which restricts inline style attributes on elements.
     */
    public static final String STYLE_SRC_ATTR = "style-src-attr";

    /**
     * The {@code style-src-elem} directive, which restricts stylesheets loaded by {@code style} and
     * stylesheet {@code link} elements.
     */
    public static final String STYLE_SRC_ELEM = "style-src-elem";

    /**
     * The {@code trusted-types} directive, which defines the Trusted Types policy names that scripts
     * may create. Use it with {@code require-trusted-types-for 'script'} to enforce those policies
     * at supported DOM injection sinks.
     */
    public static final String TRUSTED_TYPES = "trusted-types";

    /**
     * The {@code upgrade-insecure-requests} directive, which upgrades insecure HTTP resource URLs to
     * HTTPS before they are requested.
     */
    public static final String UPGRADE_INSECURE_REQUESTS = "upgrade-insecure-requests";

    /**
     * The {@code worker-src} directive, which restricts scripts loaded by web workers. Disabling workers
     * prevents untrusted worker scripts from running in a separate execution context.
     */
    public static final String WORKER_SRC = "worker-src";

    private ContentSecurityPolicyDirectiveNames() {
    }
}
