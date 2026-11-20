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
 * Keywords and scheme sources used as Content Security Policy source expressions.
 *
 * <p>Keyword source expressions, such as {@code 'self'}, are written with single quotes in a policy;
 * the constants without a {@code QUOTED_} prefix hold the keyword without its quotes. Scheme sources,
 * such as {@code https:}, are written without quotes.</p>
 *
 * @see <a href="https://www.w3.org/TR/CSP3/#framework-directive-source-list">Source lists</a>
 * @since 5.6.0
 */
public final class ContentSecurityPolicyKeywords {
    /**
     * The {@code self} keyword source expression, without its surrounding quotes.
     */
    public static final String SELF = "self";

    /**
     * The {@code 'self'} keyword source expression, including the required single quotes.
     */
    public static final String QUOTED_SELF = "'self'";

    /**
     * The {@code none} keyword source expression, without its surrounding quotes.
     */
    public static final String NONE = "none";

    /**
     * The {@code 'none'} keyword source expression, including the required single quotes.
     */
    public static final String QUOTED_NONE = "'none'";

    /**
     * The {@code script} Trusted Types sink group, without its surrounding quotes.
     */
    public static final String SCRIPT = "script";

    /**
     * The {@code strict-dynamic} keyword, which delegates trust to scripts loaded by a nonce- or
     * hash-authorized script. In CSP3-capable browsers, host source expressions are ignored when
     * this keyword is paired with a nonce or hash.
     */
    public static final String STRICT_DYNAMIC = "strict-dynamic";

    /**
     * The {@code unsafe-inline} keyword, which permits inline scripts that are not authorized by
     * a nonce or hash. Enabling it weakens CSP's protection against cross-site scripting.
     */
    public static final String UNSAFE_INLINE = "unsafe-inline";

    /**
     * The {@code unsafe-eval} keyword, which permits JavaScript string-to-code APIs such as
     * {@code eval}. Enabling it weakens CSP's protection against cross-site scripting.
     */
    public static final String UNSAFE_EVAL = "unsafe-eval";

    /**
     * The {@code unsafe-hashes} keyword, which lets hash sources authorize inline event handlers
     * and {@code style} attributes.
     */
    public static final String UNSAFE_HASHES = "unsafe-hashes";

    /**
     * The {@code report-sample} keyword, which asks the browser to include a sample of the
     * violating code in violation reports.
     */
    public static final String REPORT_SAMPLE = "report-sample";

    /**
     * The {@code wasm-unsafe-eval} keyword, which permits WebAssembly compilation without
     * permitting JavaScript {@code eval}.
     */
    public static final String WASM_UNSAFE_EVAL = "wasm-unsafe-eval";

    /**
     * The {@code trusted-types-eval} keyword, which permits {@code eval} with Trusted Types.
     */
    public static final String TRUSTED_TYPES_EVAL = "trusted-types-eval";

    /**
     * The {@code report-sha256} keyword, which asks the browser to report SHA-256 hashes of loaded scripts.
     */
    public static final String REPORT_SHA256 = "report-sha256";

    /**
     * The {@code report-sha384} keyword, which asks the browser to report SHA-384 hashes of loaded scripts.
     */
    public static final String REPORT_SHA384 = "report-sha384";

    /**
     * The {@code report-sha512} keyword, which asks the browser to report SHA-512 hashes of loaded scripts.
     */
    public static final String REPORT_SHA512 = "report-sha512";

    /**
     * The {@code unsafe-webtransport-hashes} keyword, which lets WebTransport connections be
     * authorized by certificate hashes.
     */
    public static final String UNSAFE_WEBTRANSPORT_HASHES = "unsafe-webtransport-hashes";

    /**
     * The HTTP scheme source expression. Scheme sources are not enclosed in single quotes.
     */
    public static final String HTTP = "http:";

    /**
     * The HTTPS scheme source expression. Scheme sources are not enclosed in single quotes.
     */
    public static final String HTTPS = "https:";

    /**
     * The data URL scheme source expression. Scheme sources are not enclosed in single quotes.
     */
    public static final String DATA = "data:";

    /**
     * The blob URL scheme source expression. Scheme sources are not enclosed in single quotes.
     */
    public static final String BLOB = "blob:";

    /**
     * The filesystem URL scheme source expression. Scheme sources are not enclosed in single quotes.
     */
    public static final String FILESYSTEM = "filesystem:";

    /**
     * The media stream URL scheme source expression. Scheme sources are not enclosed in single quotes.
     */
    public static final String MEDIASTREAM = "mediastream:";

    /**
     * The WebSocket scheme source expression. Scheme sources are not enclosed in single quotes.
     */
    public static final String WS = "ws:";

    /**
     * The secure WebSocket scheme source expression. Scheme sources are not enclosed in single quotes.
     */
    public static final String WSS = "wss:";

    private ContentSecurityPolicyKeywords() {
    }
}
