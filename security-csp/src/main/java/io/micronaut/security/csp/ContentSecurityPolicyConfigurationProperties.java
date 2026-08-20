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

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.annotation.Internal;

import java.util.Collections;
import java.util.List;

import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.NONE;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.SCRIPT;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.SELF;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.SINGLE_QUOTE;

/**
 * Binds the {@code micronaut.security.csp} configuration namespace to the default CSP policy.
 *
 * <p>Defaults deny source-list directives unless a directive deliberately needs a narrower
 * application-compatible default, such as {@code form-action 'self'}.</p>
 */
@ConfigurationProperties("micronaut.security.csp")
@Internal
final class ContentSecurityPolicyConfigurationProperties implements ContentSecurityPolicyConfiguration {
    private static final List<String> SELF_VALUES = List.of(SINGLE_QUOTE + SELF + SINGLE_QUOTE);
    private static final List<String> NONE_VALUES = List.of(SINGLE_QUOTE + NONE + SINGLE_QUOTE);
    private static final String SCRIPT_VALUE = SINGLE_QUOTE + SCRIPT + SINGLE_QUOTE;
    private static final boolean DEFAULT_ENABLED = true;
    private static final boolean DEFAULT_REPORT_ONLY = false;
    private static final boolean DEFAULT_BASE_URI_ENABLED = true;
    private static final List<String> DEFAULT_BASE_URI_VALUE = NONE_VALUES;
    private static final boolean DEFAULT_DEFAULT_SRC_ENABLED = true;
    private static final List<String> DEFAULT_DEFAULT_SRC_VALUE = NONE_VALUES;
    private static final boolean DEFAULT_CONNECT_SRC_ENABLED = true;
    private static final List<String> DEFAULT_CONNECT_SRC_VALUE = NONE_VALUES;
    private static final boolean DEFAULT_FENCED_FRAME_SRC_ENABLED = false;
    private static final List<String> DEFAULT_FENCED_FRAME_SRC_VALUE = NONE_VALUES;
    private static final boolean DEFAULT_FONT_SRC_ENABLED = true;
    private static final List<String> DEFAULT_FONT_SRC_VALUE = NONE_VALUES;
    private static final boolean DEFAULT_OBJECT_SRC_ENABLED = true;
    private static final List<String> DEFAULT_OBJECT_SRC_VALUE = NONE_VALUES;
    private static final boolean DEFAULT_PREFETCH_SRC_ENABLED = true;
    private static final List<String> DEFAULT_PREFETCH_SRC_VALUE = NONE_VALUES;
    private static final boolean DEFAULT_REPORT_URI_ENABLED = false;
    private static final List<String> DEFAULT_REPORT_URI_VALUE = Collections.emptyList();
    private static final boolean DEFAULT_REQUIRE_TRUSTED_TYPES_FOR_ENABLED = true;
    private static final String DEFAULT_REQUIRE_TRUSTED_TYPES_FOR_VALUE = SCRIPT_VALUE;
    private static final boolean DEFAULT_FRAME_ANCESTORS_ENABLED = true;
    private static final List<String> DEFAULT_FRAME_ANCESTORS_VALUE = NONE_VALUES;
    private static final boolean DEFAULT_FRAME_SRC_ENABLED = true;
    private static final List<String> DEFAULT_FRAME_SRC_VALUE = NONE_VALUES;
    private static final boolean DEFAULT_IMG_SRC_ENABLED = true;
    private static final List<String> DEFAULT_IMG_SRC_VALUE = NONE_VALUES;
    private static final boolean DEFAULT_MANIFEST_SRC_ENABLED = true;
    private static final List<String> DEFAULT_MANIFEST_SRC_VALUE = NONE_VALUES;
    private static final boolean DEFAULT_MEDIA_SRC_ENABLED = true;
    private static final List<String> DEFAULT_MEDIA_SRC_VALUE = NONE_VALUES;
    private static final boolean DEFAULT_FORM_ACTION_ENABLED = true;
    private static final List<String> DEFAULT_FORM_ACTION_VALUE = SELF_VALUES;
    private static final boolean DEFAULT_SCRIPT_SRC_NONCE_ENABLED = true;
    private static final boolean DEFAULT_SCRIPT_SRC_STRICT_DYNAMIC = false;
    private static final boolean DEFAULT_SCRIPT_SRC_SELF = false;
    private static final List<String> DEFAULT_SCRIPT_SRC_HASHES = Collections.emptyList();
    private static final List<String> DEFAULT_SCRIPT_SRC_URLS = Collections.emptyList();
    private static final boolean DEFAULT_SCRIPT_SRC_UNSAFE_INLINE = false;
    private static final boolean DEFAULT_SCRIPT_SRC_UNSAFE_EVAL = false;
    private static final boolean DEFAULT_SCRIPT_SRC_HTTP = false;
    private static final boolean DEFAULT_SCRIPT_SRC_HTTPS = false;
    private static final boolean DEFAULT_STYLE_SRC_ENABLED = true;
    private static final List<String> DEFAULT_STYLE_SRC_VALUE = NONE_VALUES;
    private static final boolean DEFAULT_WORKER_SRC_ENABLED = true;
    private static final List<String> DEFAULT_WORKER_SRC_VALUE = NONE_VALUES;
    private boolean enabled = DEFAULT_ENABLED;
    private boolean reportOnly = DEFAULT_REPORT_ONLY;
    private boolean baseUriEnabled = DEFAULT_BASE_URI_ENABLED;
    private List<String> baseUri = DEFAULT_BASE_URI_VALUE;
    private boolean defaultSrcEnabled = DEFAULT_DEFAULT_SRC_ENABLED;
    private List<String> defaultSrc = DEFAULT_DEFAULT_SRC_VALUE;
    private boolean connectSrcEnabled = DEFAULT_CONNECT_SRC_ENABLED;
    private List<String> connectSrc = DEFAULT_CONNECT_SRC_VALUE;
    private boolean fencedFrameSrcEnabled = DEFAULT_FENCED_FRAME_SRC_ENABLED;
    private List<String> fencedFrameSrc = DEFAULT_FENCED_FRAME_SRC_VALUE;
    private boolean fontSrcEnabled = DEFAULT_FONT_SRC_ENABLED;
    private List<String> fontSrc = DEFAULT_FONT_SRC_VALUE;
    private boolean objectSrcEnabled = DEFAULT_OBJECT_SRC_ENABLED;
    private List<String> objectSrc = DEFAULT_OBJECT_SRC_VALUE;
    private boolean prefetchSrcEnabled = DEFAULT_PREFETCH_SRC_ENABLED;
    private List<String> prefetchSrc = DEFAULT_PREFETCH_SRC_VALUE;
    private boolean reportUriEnabled = DEFAULT_REPORT_URI_ENABLED;
    private List<String> reportUri = DEFAULT_REPORT_URI_VALUE;
    private boolean requireTrustedTypesForEnabled = DEFAULT_REQUIRE_TRUSTED_TYPES_FOR_ENABLED;
    private String requireTrustedTypesFor = DEFAULT_REQUIRE_TRUSTED_TYPES_FOR_VALUE;
    private boolean frameAncestorsEnabled = DEFAULT_FRAME_ANCESTORS_ENABLED;
    private List<String> frameAncestors = DEFAULT_FRAME_ANCESTORS_VALUE;
    private boolean frameSrcEnabled = DEFAULT_FRAME_SRC_ENABLED;
    private List<String> frameSrc = DEFAULT_FRAME_SRC_VALUE;
    private boolean imgSrcEnabled = DEFAULT_IMG_SRC_ENABLED;
    private List<String> imgSrc = DEFAULT_IMG_SRC_VALUE;
    private boolean manifestSrcEnabled = DEFAULT_MANIFEST_SRC_ENABLED;
    private List<String> manifestSrc = DEFAULT_MANIFEST_SRC_VALUE;
    private boolean mediaSrcEnabled = DEFAULT_MEDIA_SRC_ENABLED;
    private List<String> mediaSrc = DEFAULT_MEDIA_SRC_VALUE;
    private boolean formActionEnabled = DEFAULT_FORM_ACTION_ENABLED;
    private List<String> formAction = DEFAULT_FORM_ACTION_VALUE;
    private boolean scriptSrcNonceEnabled = DEFAULT_SCRIPT_SRC_NONCE_ENABLED;
    private boolean scriptSrcStrictDynamic = DEFAULT_SCRIPT_SRC_STRICT_DYNAMIC;
    private boolean scriptSrcSelf = DEFAULT_SCRIPT_SRC_SELF;
    private List<String> scriptSrcHashes = DEFAULT_SCRIPT_SRC_HASHES;
    private List<String> scriptSrcUrls = DEFAULT_SCRIPT_SRC_URLS;
    private boolean scriptSrcUnsafeInline = DEFAULT_SCRIPT_SRC_UNSAFE_INLINE;
    private boolean scriptSrcUnsafeEval = DEFAULT_SCRIPT_SRC_UNSAFE_EVAL;
    private boolean scriptSrcHttp = DEFAULT_SCRIPT_SRC_HTTP;
    private boolean scriptSrcHttps = DEFAULT_SCRIPT_SRC_HTTPS;
    private boolean styleSrcEnabled = DEFAULT_STYLE_SRC_ENABLED;
    private List<String> styleSrc = DEFAULT_STYLE_SRC_VALUE;
    private boolean workerSrcEnabled = DEFAULT_WORKER_SRC_ENABLED;
    private List<String> workerSrc = DEFAULT_WORKER_SRC_VALUE;

    @Override
    public boolean isBaseUriEnabled() {
        return baseUriEnabled;
    }

    /**
     * @param baseUriEnabled whether the {@code base-uri} directive is included in the policy
     */
    public void setBaseUriEnabled(boolean baseUriEnabled) {
        this.baseUriEnabled = baseUriEnabled;
    }

    @Override
    public List<String> getBaseUri() {
        return baseUri;
    }

    /**
     * @param baseUri the source expression used as the value of the {@code base-uri} directive
     */
    public void setBaseUri(List<String> baseUri) {
        this.baseUri = baseUri;
    }

    @Override
    public boolean isDefaultSrcEnabled() {
        return defaultSrcEnabled;
    }

    /**
     * @param defaultSrcEnabled whether the {@code default-src} directive is included in the policy
     */
    public void setDefaultSrcEnabled(boolean defaultSrcEnabled) {
        this.defaultSrcEnabled = defaultSrcEnabled;
    }

    @Override
    public List<String> getDefaultSrc() {
        return defaultSrc;
    }

    /**
     * @param defaultSrc the fallback source expressions for fetch directives not explicitly configured
     */
    public void setDefaultSrc(List<String> defaultSrc) {
        this.defaultSrc = defaultSrc;
    }

    @Override
    public boolean isConnectSrcEnabled() {
        return connectSrcEnabled;
    }

    /** @param connectSrcEnabled whether the {@code connect-src} directive is included in the policy */
    public void setConnectSrcEnabled(boolean connectSrcEnabled) {
        this.connectSrcEnabled = connectSrcEnabled;
    }

    @Override
    public List<String> getConnectSrc() {
        return connectSrc;
    }

    /** @param connectSrc the source expressions used as the value of the {@code connect-src} directive */
    public void setConnectSrc(List<String> connectSrc) {
        this.connectSrc = connectSrc;
    }

    @Override
    public boolean isFencedFrameSrcEnabled() {
        return fencedFrameSrcEnabled;
    }

    /**
     * @param fencedFrameSrcEnabled whether the {@code fenced-frame-src} directive is included in the policy
     */
    public void setFencedFrameSrcEnabled(boolean fencedFrameSrcEnabled) {
        this.fencedFrameSrcEnabled = fencedFrameSrcEnabled;
    }

    @Override
    public List<String> getFencedFrameSrc() {
        return fencedFrameSrc;
    }

    /**
     * @param fencedFrameSrc the source expressions used as the value of the {@code fenced-frame-src} directive
     */
    public void setFencedFrameSrc(List<String> fencedFrameSrc) {
        this.fencedFrameSrc = fencedFrameSrc;
    }

    @Override
    public boolean isFontSrcEnabled() {
        return fontSrcEnabled;
    }

    /** @param fontSrcEnabled whether the {@code font-src} directive is included in the policy */
    public void setFontSrcEnabled(boolean fontSrcEnabled) {
        this.fontSrcEnabled = fontSrcEnabled;
    }

    @Override
    public List<String> getFontSrc() {
        return fontSrc;
    }

    /** @param fontSrc the source expressions used as the value of the {@code font-src} directive */
    public void setFontSrc(List<String> fontSrc) {
        this.fontSrc = fontSrc;
    }

    @Override
    public boolean isObjectSrcEnabled() {
        return objectSrcEnabled;
    }

    /**
     * @param objectSrcEnabled whether the {@code object-src} directive is included in the policy
     */
    public void setObjectSrcEnabled(boolean objectSrcEnabled) {
        this.objectSrcEnabled = objectSrcEnabled;
    }

    @Override
    public List<String> getObjectSrc() {
        return objectSrc;
    }

    /**
     * @param objectSrc the source expression used as the value of the {@code object-src} directive
     */
    public void setObjectSrc(List<String> objectSrc) {
        this.objectSrc = objectSrc;
    }

    @Override
    public boolean isPrefetchSrcEnabled() {
        return prefetchSrcEnabled;
    }

    /** @param prefetchSrcEnabled whether the {@code prefetch-src} directive is included in the policy */
    public void setPrefetchSrcEnabled(boolean prefetchSrcEnabled) {
        this.prefetchSrcEnabled = prefetchSrcEnabled;
    }

    @Override
    public List<String> getPrefetchSrc() {
        return prefetchSrc;
    }

    /** @param prefetchSrc the source expressions used as the value of the {@code prefetch-src} directive */
    public void setPrefetchSrc(List<String> prefetchSrc) {
        this.prefetchSrc = prefetchSrc;
    }

    @Override
    public boolean isReportUriEnabled() {
        return reportUriEnabled;
    }

    /**
     * @param reportUriEnabled whether the deprecated {@code report-uri} directive is included in the policy
     */
    public void setReportUriEnabled(boolean reportUriEnabled) {
        this.reportUriEnabled = reportUriEnabled;
    }

    @Override
    public List<String> getReportUri() {
        return reportUri;
    }

    /**
     * @param reportUri the endpoint URLs used as the value of the deprecated {@code report-uri} directive
     */
    public void setReportUri(List<String> reportUri) {
        this.reportUri = reportUri;
    }

    @Override
    public boolean isRequireTrustedTypesForEnabled() {
        return requireTrustedTypesForEnabled;
    }

    /** @param requireTrustedTypesForEnabled whether the {@code require-trusted-types-for} directive is included in the policy */
    public void setRequireTrustedTypesForEnabled(boolean requireTrustedTypesForEnabled) {
        this.requireTrustedTypesForEnabled = requireTrustedTypesForEnabled;
    }

    @Override
    public String getRequireTrustedTypesFor() {
        return requireTrustedTypesFor;
    }

    /** @param requireTrustedTypesFor the sink group required to use Trusted Types */
    public void setRequireTrustedTypesFor(String requireTrustedTypesFor) {
        this.requireTrustedTypesFor = requireTrustedTypesFor;
    }

    @Override
    public boolean isFrameAncestorsEnabled() {
        return frameAncestorsEnabled;
    }

    /**
     * @param frameAncestorsEnabled whether the {@code frame-ancestors} directive is included in the policy
     */
    public void setFrameAncestorsEnabled(boolean frameAncestorsEnabled) {
        this.frameAncestorsEnabled = frameAncestorsEnabled;
    }

    @Override
    public List<String> getFrameAncestors() {
        return frameAncestors;
    }

    /**
     * @param frameAncestors the source expression used as the value of the {@code frame-ancestors} directive
     */
    public void setFrameAncestors(List<String> frameAncestors) {
        this.frameAncestors = frameAncestors;
    }

    @Override
    public boolean isFrameSrcEnabled() {
        return frameSrcEnabled;
    }

    /**
     * @param frameSrcEnabled whether the {@code frame-src} directive is included in the policy
     */
    public void setFrameSrcEnabled(boolean frameSrcEnabled) {
        this.frameSrcEnabled = frameSrcEnabled;
    }

    @Override
    public List<String> getFrameSrc() {
        return frameSrc;
    }

    /**
     * @param frameSrc the source expression used as the value of the {@code frame-src} directive
     */
    public void setFrameSrc(List<String> frameSrc) {
        this.frameSrc = frameSrc;
    }

    @Override
    public boolean isImgSrcEnabled() {
        return imgSrcEnabled;
    }

    /** @param imgSrcEnabled whether the {@code img-src} directive is included in the policy */
    public void setImgSrcEnabled(boolean imgSrcEnabled) {
        this.imgSrcEnabled = imgSrcEnabled;
    }

    @Override
    public List<String> getImgSrc() {
        return imgSrc;
    }

    /** @param imgSrc the source expressions used as the value of the {@code img-src} directive */
    public void setImgSrc(List<String> imgSrc) {
        this.imgSrc = imgSrc;
    }

    @Override
    public boolean isManifestSrcEnabled() {
        return manifestSrcEnabled;
    }

    /** @param manifestSrcEnabled whether the {@code manifest-src} directive is included in the policy */
    public void setManifestSrcEnabled(boolean manifestSrcEnabled) {
        this.manifestSrcEnabled = manifestSrcEnabled;
    }

    @Override
    public List<String> getManifestSrc() {
        return manifestSrc;
    }

    /** @param manifestSrc the source expressions used as the value of the {@code manifest-src} directive */
    public void setManifestSrc(List<String> manifestSrc) {
        this.manifestSrc = manifestSrc;
    }

    @Override
    public boolean isMediaSrcEnabled() {
        return mediaSrcEnabled;
    }

    /** @param mediaSrcEnabled whether the {@code media-src} directive is included in the policy */
    public void setMediaSrcEnabled(boolean mediaSrcEnabled) {
        this.mediaSrcEnabled = mediaSrcEnabled;
    }

    @Override
    public List<String> getMediaSrc() {
        return mediaSrc;
    }

    /** @param mediaSrc the source expressions used as the value of the {@code media-src} directive */
    public void setMediaSrc(List<String> mediaSrc) {
        this.mediaSrc = mediaSrc;
    }

    @Override
    public boolean isFormActionEnabled() {
        return formActionEnabled;
    }

    /**
     * @param formActionEnabled whether the {@code form-action} directive is included in the policy
     */
    public void setFormActionEnabled(boolean formActionEnabled) {
        this.formActionEnabled = formActionEnabled;
    }

    @Override
    public List<String> getFormAction() {
        return formAction;
    }

    /**
     * @param formAction the source expression used as the value of the {@code form-action} directive
     */
    public void setFormAction(List<String> formAction) {
        this.formAction = formAction;
    }

    @Override
    public boolean isScriptSrcNonceEnabled() {
        return scriptSrcNonceEnabled;
    }

    /**
     * @param scriptSrcNonceEnabled whether a per-response nonce is added to the {@code script-src} directive
     */
    public void setScriptSrcNonceEnabled(boolean scriptSrcNonceEnabled) {
        this.scriptSrcNonceEnabled = scriptSrcNonceEnabled;
    }

    @Override
    public boolean isScriptSrcStrictDynamic() {
        return scriptSrcStrictDynamic;
    }

    /**
     * @param scriptSrcStrictDynamic whether {@code 'strict-dynamic'} is added to the {@code script-src} directive
     */
    public void setScriptSrcStrictDynamic(boolean scriptSrcStrictDynamic) {
        this.scriptSrcStrictDynamic = scriptSrcStrictDynamic;
    }

    @Override
    public boolean isScriptSrcSelf() {
        return scriptSrcSelf;
    }

    /**
     * @param scriptSrcSelf whether {@code 'self'} is added to the {@code script-src} directive
     */
    public void setScriptSrcSelf(boolean scriptSrcSelf) {
        this.scriptSrcSelf = scriptSrcSelf;
    }

    @Override
    public List<String> getScriptSrcHashes() {
        return scriptSrcHashes;
    }

    /**
     * @param scriptSrcHashes hash source expressions, such as {@code sha256-...}, to add to {@code script-src}
     */
    public void setScriptSrcHashes(List<String> scriptSrcHashes) {
        this.scriptSrcHashes = scriptSrcHashes;
    }

    @Override
    public List<String> getScriptSrcUrls() {
        return scriptSrcUrls;
    }

    /**
     * @param scriptSrcUrls URL source expressions to add to the {@code script-src} directive
     */
    public void setScriptSrcUrls(List<String> scriptSrcUrls) {
        this.scriptSrcUrls = scriptSrcUrls;
    }

    @Override
    public boolean isScriptSrcUnsafeInline() {
        return scriptSrcUnsafeInline;
    }

    /**
     * @param scriptSrcUnsafeInline whether {@code 'unsafe-inline'} is added to the {@code script-src} directive
     */
    public void setScriptSrcUnsafeInline(boolean scriptSrcUnsafeInline) {
        this.scriptSrcUnsafeInline = scriptSrcUnsafeInline;
    }

    @Override
    public boolean isScriptSrcUnsafeEval() {
        return scriptSrcUnsafeEval;
    }

    /**
     * @param scriptSrcUnsafeEval whether {@code 'unsafe-eval'} is added to the {@code script-src} directive
     */
    public void setScriptSrcUnsafeEval(boolean scriptSrcUnsafeEval) {
        this.scriptSrcUnsafeEval = scriptSrcUnsafeEval;
    }

    @Override
    public boolean isScriptSrcHttp() {
        return scriptSrcHttp;
    }

    /**
     * @param scriptSrcHttp whether the unquoted {@code http:} scheme source is added to {@code script-src}
     */
    public void setScriptSrcHttp(boolean scriptSrcHttp) {
        this.scriptSrcHttp = scriptSrcHttp;
    }

    @Override
    public boolean isScriptSrcHttps() {
        return scriptSrcHttps;
    }

    /**
     * @param scriptSrcHttps whether the unquoted {@code https:} scheme source is added to {@code script-src}
     */
    public void setScriptSrcHttps(boolean scriptSrcHttps) {
        this.scriptSrcHttps = scriptSrcHttps;
    }

    @Override
    public boolean isStyleSrcEnabled() {
        return styleSrcEnabled;
    }

    /** @param styleSrcEnabled whether the {@code style-src} directive is included in the policy */
    public void setStyleSrcEnabled(boolean styleSrcEnabled) {
        this.styleSrcEnabled = styleSrcEnabled;
    }

    @Override
    public List<String> getStyleSrc() {
        return styleSrc;
    }

    /** @param styleSrc the source expressions used as the value of the {@code style-src} directive */
    public void setStyleSrc(List<String> styleSrc) {
        this.styleSrc = styleSrc;
    }

    @Override
    public boolean isWorkerSrcEnabled() {
        return workerSrcEnabled;
    }

    /**
     * @param workerSrcEnabled whether the {@code worker-src} directive is included in the policy
     */
    public void setWorkerSrcEnabled(boolean workerSrcEnabled) {
        this.workerSrcEnabled = workerSrcEnabled;
    }

    @Override
    public List<String> getWorkerSrc() {
        return workerSrc;
    }

    /**
     * @param workerSrc the source expression used as the value of the {@code worker-src} directive
     */
    public void setWorkerSrc(List<String> workerSrc) {
        this.workerSrc = workerSrc;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public boolean isReportOnly() {
        return reportOnly;
    }

    /**
     * @param reportOnly whether to send the policy using the {@code Content-Security-Policy-Report-Only} header
     */
    public void setReportOnly(boolean reportOnly) {
        this.reportOnly = reportOnly;
    }

    /**
     * @param enabled whether the CSP module is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
