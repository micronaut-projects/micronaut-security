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

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.CollectionUtils;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

/**
 * Generates the default, opt-out CSP directive set from {@link ContentSecurityPolicyConfiguration}.
 *
 * <p>Source-list configuration values are joined using CSP's space-separated syntax. Per-request
 * script directives are generated separately because their nonce is request-specific.</p>
 *
 * <p>Subclasses can override the protected directive methods to replace or omit an individual
 * directive without reimplementing policy assembly.</p>
 *
 * @since 5.4.0
 */
@Requires(missingBeans = ContentSecurityPolicyGenerator.class)
@Singleton
public class DefaultContentSecurityPolicyGenerator implements ContentSecurityPolicyGenerator {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultContentSecurityPolicyGenerator.class);
    private final ContentSecurityPolicyConfiguration cspConfiguration;
    private final Function<HttpRequest<?>, @Nullable String> cspNonceProvider;

    /**
     * @param cspConfiguration configures the generated default policy
     * @since 5.4.0
     */
    @Inject
    protected DefaultContentSecurityPolicyGenerator(ContentSecurityPolicyConfiguration cspConfiguration) {
        this(cspConfiguration, req -> req.getAttribute(CspNonceGenerator.CSP_NONCE_ATTRIBUTE, String.class).orElse(null));
    }

    /**
     * @param cspConfiguration configures the generated default policy
     * @param cspNonceProvider generates and stores the request CSP nonce
     * @since 5.4.0
     */
    protected DefaultContentSecurityPolicyGenerator(ContentSecurityPolicyConfiguration cspConfiguration,
                                                    Function<HttpRequest<?>, @Nullable String> cspNonceProvider) {
        this.cspConfiguration = cspConfiguration;
        this.cspNonceProvider = cspNonceProvider;
    }

    @Override
    public List<CspDirective> contentSecurityPolicy() {
        List<@Nullable CspDirective> directives = new ArrayList<>();
        directives.add(baseUri());
        directives.add(defaultSrc());
        directives.add(connectSrc());
        directives.add(fencedFrameSrc());
        directives.add(fontSrc());
        directives.add(objectSrc());
        directives.add(prefetchSrc());
        directives.add(reportUri());
        directives.add(requireTrustedTypesFor());
        directives.add(frameAncestors());
        directives.add(frameSrc());
        directives.add(imgSrc());
        directives.add(manifestSrc());
        directives.add(mediaSrc());
        directives.add(formAction());
        directives.add(styleSrc());
        directives.add(workerSrc());
        return directives.stream().filter(Objects::nonNull).toList();
    }

    /**
     * Adds the request-specific {@code script-src} directive to the configured baseline policy.
     *
     * @param request the request whose nonce is used to build the policy
     * @return the complete policy for the request
     */
    @Override
    public List<CspDirective> contentSecurityPolicy(HttpRequest<?> request) {
        List<@Nullable CspDirective> directives = new ArrayList<>(contentSecurityPolicy());
        directives.add(scriptSrc(request));
        return directives.stream().filter(Objects::nonNull).toList();
    }

    /**
     * Builds the nonce- and strict-dynamic-based {@code script-src} directive when either option is enabled.
     *
     * @param request the request from which to obtain the CSP nonce
     * @return the script directive, or {@code null} if it has no configured values
     * @since 5.4.0
     */
    protected @Nullable CspDirective scriptSrc(HttpRequest<?> request) {
        List<String> values = new ArrayList<>();
        if (cspConfiguration.isScriptSrcNonceEnabled()) {
            String nonce = cspNonceProvider.apply(request);
            if (StringUtils.isNotEmpty(nonce)) {
                values.add(NONCE_PREFIX + nonce);
            } else {
                if (LOG.isTraceEnabled()) {
                    LOG.trace("CSP nonce not found in request attribute {}", CspNonceGenerator.CSP_NONCE_ATTRIBUTE);
                }
            }
        }
        if (cspConfiguration.isScriptSrcStrictDynamic()) {
            values.add(STRICT_DYNAMIC);
        }
        if (cspConfiguration.isScriptSrcUnsafeInline()) {
            values.add(UNSAFE_INLINE);
        }
        if (cspConfiguration.isScriptSrcUnsafeEval()) {
            values.add(UNSAFE_EVAL);
        }
        if (cspConfiguration.isScriptSrcSelf()) {
            values.add(SELF);
        }
        values.addAll(cspConfiguration.getScriptSrcHashes());
        if (CollectionUtils.isNotEmpty(values)) {
            values = new ArrayList(values.stream()
                .map(DefaultContentSecurityPolicyGenerator::wrapInSingleQuotes)
                .toList());
        }
        if (cspConfiguration.isScriptSrcHttp()) {
            values.add(HTTP);
        }
        if (cspConfiguration.isScriptSrcHttps()) {
            values.add(HTTPS);
        }
        values.addAll(cspConfiguration.getScriptSrcUrls());
        return values.isEmpty()
                ? null
                : new CspDirective(SCRIPT_SRC, String.join(SPACE, values));
    }

    /**
     * Builds the configured {@code base-uri} directive.
     *
     * @return the base URI directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable CspDirective baseUri() {
        if (cspConfiguration.isBaseUriEnabled()) {
            return directive(BASE_URI, cspConfiguration.getBaseUri());
        }
        return null;
    }

    /**
     * @return the configured {@code default-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable CspDirective defaultSrc() {
        return cspConfiguration.isDefaultSrcEnabled() ? directive(DEFAULT_SRC, cspConfiguration.getDefaultSrc()) : null;
    }

    /**
     * @return the configured {@code connect-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable CspDirective connectSrc() {
        return cspConfiguration.isConnectSrcEnabled() ? directive(CONNECT_SRC, cspConfiguration.getConnectSrc()) : null;
    }

    /**
     * @return the configured {@code fenced-frame-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable CspDirective fencedFrameSrc() {
        return cspConfiguration.isFencedFrameSrcEnabled()
                ? directive(FENCED_FRAME_SRC, cspConfiguration.getFencedFrameSrc()) : null;
    }

    /**
     * @return the configured {@code font-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable CspDirective fontSrc() {
        return cspConfiguration.isFontSrcEnabled() ? directive(FONT_SRC, cspConfiguration.getFontSrc()) : null;
    }

    /**
     * @return the configured {@code object-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable CspDirective objectSrc() {
        return cspConfiguration.isObjectSrcEnabled() ? directive(OBJECT_SRC, cspConfiguration.getObjectSrc()) : null;
    }

    /**
     * @return the configured {@code prefetch-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable CspDirective prefetchSrc() {
        return cspConfiguration.isPrefetchSrcEnabled() ? directive(PREFETCH_SRC, cspConfiguration.getPrefetchSrc()) : null;
    }

    /**
     * @return the configured deprecated {@code report-uri} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable CspDirective reportUri() {
        return cspConfiguration.isReportUriEnabled() ? directive(REPORT_URI, cspConfiguration.getReportUri()) : null;
    }

    /**
     * @return the configured {@code require-trusted-types-for} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable CspDirective requireTrustedTypesFor() {
        return cspConfiguration.isRequireTrustedTypesForEnabled()
                ? new CspDirective(REQUIRE_TRUSTED_TYPES_FOR, cspConfiguration.getRequireTrustedTypesFor()) : null;
    }

    /**
     * @return the configured {@code frame-ancestors} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable CspDirective frameAncestors() {
        return cspConfiguration.isFrameAncestorsEnabled()
                ? directive(FRAME_ANCESTORS, cspConfiguration.getFrameAncestors()) : null;
    }

    /**
     * @return the configured {@code frame-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable CspDirective frameSrc() {
        return cspConfiguration.isFrameSrcEnabled() ? directive(FRAME_SRC, cspConfiguration.getFrameSrc()) : null;
    }

    /**
     * @return the configured {@code img-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable CspDirective imgSrc() {
        return cspConfiguration.isImgSrcEnabled() ? directive(IMG_SRC, cspConfiguration.getImgSrc()) : null;
    }

    /**
     * @return the configured {@code manifest-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable CspDirective manifestSrc() {
        return cspConfiguration.isManifestSrcEnabled()
                ? directive(MANIFEST_SRC, cspConfiguration.getManifestSrc()) : null;
    }

    /**
     * @return the configured {@code media-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable CspDirective mediaSrc() {
        return cspConfiguration.isMediaSrcEnabled() ? directive(MEDIA_SRC, cspConfiguration.getMediaSrc()) : null;
    }

    /**
     * @return the configured {@code form-action} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable CspDirective formAction() {
        return cspConfiguration.isFormActionEnabled() ? directive(FORM_ACTION, cspConfiguration.getFormAction()) : null;
    }

    /**
     * @return the configured {@code style-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable CspDirective styleSrc() {
        return cspConfiguration.isStyleSrcEnabled() ? directive(STYLE_SRC, cspConfiguration.getStyleSrc()) : null;
    }

    /**
     * @return the configured {@code worker-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable CspDirective workerSrc() {
        return cspConfiguration.isWorkerSrcEnabled() ? directive(WORKER_SRC, cspConfiguration.getWorkerSrc()) : null;
    }

    /**
     * Converts source expressions to CSP's space-separated directive representation.
     *
     * @param name the CSP directive name
     * @param values the source expressions associated with the directive
     * @return the serialized directive
     */
    private static CspDirective directive(String name, List<String> values) {
        return new CspDirective(name, String.join(SPACE, values.stream()
            .filter(StringUtils::isNotEmpty)
            .toList()));
    }

    private static String wrapInSingleQuotes(String value) {
        if (value.startsWith(SINGLE_QUOTE) && value.endsWith(SINGLE_QUOTE)) {
            return value;
        }
        return SINGLE_QUOTE + value +  SINGLE_QUOTE;
    }
}
