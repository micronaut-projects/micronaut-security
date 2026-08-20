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

import io.micronaut.http.HttpRequest;

import java.util.List;

/**
 * Generates the directives for a Content Security Policy response header.
 *
 * @since 5.4.0
 */
@FunctionalInterface
public interface ContentSecurityPolicyGenerator {
    String STRICT_DYNAMIC = "strict-dynamic";

    /**
     * The {@code base-uri} directive, which restricts the URLs that a document's {@code base} element
     * may use. This prevents injected markup from changing how relative URLs resolve.
     */
    String BASE_URI = "base-uri";
    /**
     * The {@code child-src} directive, which restricts nested browsing contexts and worker scripts.
     * It is a fallback for {@code frame-src} and {@code worker-src} in supporting browsers.
     */
    String CHILD_SRC = "child-src";
    /**
     * The {@code connect-src} directive, which restricts URLs used by script interfaces such as
     * {@code fetch}, {@code XMLHttpRequest}, WebSocket, and EventSource.
     */
    String CONNECT_SRC = "connect-src";
    /**
     * The {@code default-src} directive, which supplies a fallback source list for fetch directives
     * that are not explicitly configured.
     */
    String DEFAULT_SRC = "default-src";
    /**
     * The {@code font-src} directive, which restricts fonts loaded through {@code @font-face}.
     */
    String FONT_SRC = "font-src";
    /**
     * The {@code form-action} directive, which restricts the URLs to which a document may submit forms.
     * This prevents a compromised page from submitting form data to an untrusted origin.
     */
    String FORM_ACTION = "form-action";
    /**
     * The {@code frame-ancestors} directive, which restricts the origins allowed to embed the document.
     * This helps protect the application from clickjacking.
     */
    String FRAME_ANCESTORS = "frame-ancestors";
    /**
     * The {@code frame-src} directive, which restricts documents loaded by {@code frame} and
     * {@code iframe} elements. Disabling nested documents reduces the risk of rendering untrusted content.
     */
    String FRAME_SRC = "frame-src";
    /**
     * The {@code img-src} directive, which restricts images and favicons. It can prevent injected
     * markup from making unexpected requests through image loads.
     */
    String IMG_SRC = "img-src";
    /**
     * The {@code manifest-src} directive, which restricts web application manifest files.
     */
    String MANIFEST_SRC = "manifest-src";
    /**
     * The {@code media-src} directive, which restricts media loaded by {@code audio}, {@code video},
     * and {@code track} elements.
     */
    String MEDIA_SRC = "media-src";
    /**
     * The {@code object-src} directive, which restricts plugin content loaded by {@code object} and
     * {@code embed} elements. Disabling this legacy content reduces an application's attack surface.
     */
    String OBJECT_SRC = "object-src";
    /**
     * The {@code prefetch-src} directive, which restricts resources fetched speculatively through
     * prefetching or prerendering.
     */
    String PREFETCH_SRC = "prefetch-src";
    /**
     * The {@code report-to} directive, which selects a Reporting API endpoint group to receive CSP
     * violation reports.
     */
    String REPORT_TO = "report-to";
    /**
     * The {@code require-trusted-types-for} directive, which requires Trusted Types at selected DOM
     * injection sinks and can reduce client-side XSS risk.
     */
    String REQUIRE_TRUSTED_TYPES_FOR = "require-trusted-types-for";
    /**
     * The {@code sandbox} directive, which applies sandbox restrictions to the document in a similar
     * way to the {@code sandbox} attribute on an {@code iframe}.
     */
    String SANDBOX = "sandbox";
    /**
     * The {@code script-src} directive, which restricts JavaScript and WebAssembly resources. It is a
     * primary defence-in-depth control against cross-site scripting.
     */
    String SCRIPT_SRC = "script-src";
    /**
     * The {@code script-src-attr} directive, which restricts inline JavaScript event-handler attributes.
     */
    String SCRIPT_SRC_ATTR = "script-src-attr";
    /**
     * The {@code script-src-elem} directive, which restricts JavaScript loaded by {@code script}
     * elements.
     */
    String SCRIPT_SRC_ELEM = "script-src-elem";
    /**
     * The {@code style-src} directive, which restricts stylesheets and inline style blocks.
     */
    String STYLE_SRC = "style-src";
    /**
     * The {@code style-src-attr} directive, which restricts inline style attributes on elements.
     */
    String STYLE_SRC_ATTR = "style-src-attr";
    /**
     * The {@code style-src-elem} directive, which restricts stylesheets loaded by {@code style} and
     * stylesheet {@code link} elements.
     */
    String STYLE_SRC_ELEM = "style-src-elem";
    /**
     * The {@code trusted-types} directive, which defines the Trusted Types policy names that scripts
     * may create.
     */
    String TRUSTED_TYPES = "trusted-types";
    /**
     * The {@code upgrade-insecure-requests} directive, which upgrades insecure HTTP resource URLs to
     * HTTPS before they are requested.
     */
    String UPGRADE_INSECURE_REQUESTS = "upgrade-insecure-requests";
    /**
     * The {@code worker-src} directive, which restricts scripts loaded by web workers. Disabling workers
     * prevents untrusted worker scripts from running in a separate execution context.
     */
    String WORKER_SRC = "worker-src";

    /**
     * @return the policy directives, in the order in which they should appear in the response header
     */
    List<CspDirective> contentSecurityPolicy();

    /**
     * Generates the policy directives for a request.
     *
     * @param request the request for which the policy is generated
     * @return the policy directives, in the order in which they should appear in the response header
     * @since 5.4.0
     */
    default List<CspDirective> contentSecurityPolicy(HttpRequest<?> request) {
        return contentSecurityPolicy();
    }
}
