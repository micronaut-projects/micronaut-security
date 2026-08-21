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
import io.micronaut.security.csp.conf.NonceConfiguration;
import io.micronaut.security.csp.conf.baseUri.BaseUriConfiguration;
import io.micronaut.security.csp.conf.connectSrc.ConnectSrcConfiguration;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfiguration;
import io.micronaut.security.csp.conf.DirectiveConfiguration;
import io.micronaut.security.csp.conf.SourceListDirectiveConfiguration;
import io.micronaut.security.csp.conf.defaultSrc.DefaultSrcConfiguration;
import io.micronaut.security.csp.conf.fencedFrameSrc.FencedFrameSrcConfiguration;
import io.micronaut.security.csp.conf.fontSrc.FontSrcConfiguration;
import io.micronaut.security.csp.conf.formAction.FormActionConfiguration;
import io.micronaut.security.csp.conf.frameAncestors.FrameAncestorsConfiguration;
import io.micronaut.security.csp.conf.frameSrc.FrameSrcConfiguration;
import io.micronaut.security.csp.conf.imgSrc.ImgSrcConfiguration;
import io.micronaut.security.csp.conf.manifestSrc.ManifestSrcConfiguration;
import io.micronaut.security.csp.conf.mediaSrc.MediaSrcConfiguration;
import io.micronaut.security.csp.conf.objectSrc.ObjectSrcConfiguration;
import io.micronaut.security.csp.conf.prefetchSrc.PrefetchSrcConfiguration;
import io.micronaut.security.csp.conf.reportTo.ReportToConfiguration;
import io.micronaut.security.csp.conf.reportTo.ReportToConfigurationProperties;
import io.micronaut.security.csp.conf.scriptSrc.ScriptSrcConfiguration;
import io.micronaut.security.csp.conf.styleSrc.StyleSrcConfiguration;
import io.micronaut.security.csp.conf.workerSrc.WorkerSrcConfiguration;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;
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
 * Generates the default, opt-out CSP directive set from the root and directive-specific configuration.
 *
 * <p>Each source-list directive is supplied by its own configuration contract. Directives that
 * may contain a nonce are generated from the request-specific policy method because a nonce is
 * valid for only one request.</p>
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
    private final BaseUriConfiguration baseUriConfiguration;
    private final DefaultSrcConfiguration defaultSrcConfiguration;
    private final ConnectSrcConfiguration connectSrcConfiguration;
    private final FencedFrameSrcConfiguration fencedFrameSrcConfiguration;
    private final FontSrcConfiguration fontSrcConfiguration;
    private final ObjectSrcConfiguration objectSrcConfiguration;
    private final PrefetchSrcConfiguration prefetchSrcConfiguration;
    private final ReportToConfiguration reportToConfiguration;
    private final ScriptSrcConfiguration scriptSrcConfiguration;
    private final FrameAncestorsConfiguration frameAncestorsConfiguration;
    private final FrameSrcConfiguration frameSrcConfiguration;
    private final ImgSrcConfiguration imgSrcConfiguration;
    private final ManifestSrcConfiguration manifestSrcConfiguration;
    private final MediaSrcConfiguration mediaSrcConfiguration;
    private final FormActionConfiguration formActionConfiguration;
    private final StyleSrcConfiguration styleSrcConfiguration;
    private final WorkerSrcConfiguration workerSrcConfiguration;
    private final Function<HttpRequest<?>, @Nullable String> cspNonceProvider;

    /**
     * Creates a generator with the default configuration for each directive.
     *
     * <p>This convenience constructor is intended for subclasses and tests. The injected
     * constructor receives the application-bound directive configurations.</p>
     *
     * @param cspConfiguration root CSP configuration
     */
    protected DefaultContentSecurityPolicyGenerator(ContentSecurityPolicyConfiguration cspConfiguration) {
        this(cspConfiguration,
            req -> req.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, String.class).orElse(null),
            new io.micronaut.security.csp.conf.baseUri.BaseUriConfigurationProperties(),
            new io.micronaut.security.csp.conf.defaultSrc.DefaultSrcConfigurationProperties(),
            new io.micronaut.security.csp.conf.connectSrc.ConnectSrcConfigurationProperties(),
            new io.micronaut.security.csp.conf.fencedFrameSrc.FencedFrameSrcConfigurationProperties(),
            new io.micronaut.security.csp.conf.fontSrc.FontSrcConfigurationProperties(),
            new io.micronaut.security.csp.conf.objectSrc.ObjectSrcConfigurationProperties(),
            new io.micronaut.security.csp.conf.prefetchSrc.PrefetchSrcConfigurationProperties(),
            new ReportToConfigurationProperties(),
            new io.micronaut.security.csp.conf.scriptSrc.ScriptSrcConfigurationProperties(),
            new io.micronaut.security.csp.conf.frameAncestors.FrameAncestorsConfigurationProperties(),
            new io.micronaut.security.csp.conf.frameSrc.FrameSrcConfigurationProperties(),
            new io.micronaut.security.csp.conf.imgSrc.ImgSrcConfigurationProperties(),
            new io.micronaut.security.csp.conf.manifestSrc.ManifestSrcConfigurationProperties(),
            new io.micronaut.security.csp.conf.mediaSrc.MediaSrcConfigurationProperties(),
            new io.micronaut.security.csp.conf.formAction.FormActionConfigurationProperties(),
            new io.micronaut.security.csp.conf.styleSrc.StyleSrcConfigurationProperties(),
            new io.micronaut.security.csp.conf.workerSrc.WorkerSrcConfigurationProperties());
    }

    /**
     * Creates a default policy generator from the root and directive-specific configuration.
     *
     * @param cspConfiguration configures the static policy directives
     * @param baseUriConfiguration configures {@code base-uri}
     * @param defaultSrcConfiguration configures {@code default-src}
     * @param connectSrcConfiguration configures {@code connect-src}
     * @param fencedFrameSrcConfiguration configures {@code fenced-frame-src}
     * @param fontSrcConfiguration configures {@code font-src}
     * @param objectSrcConfiguration configures {@code object-src}
     * @param prefetchSrcConfiguration configures {@code prefetch-src}
     * @param reportToConfiguration configures {@code report-to}
     * @param scriptSrcConfiguration configures {@code script-src}
     * @param frameAncestorsConfiguration configures {@code frame-ancestors}
     * @param frameSrcConfiguration configures {@code frame-src}
     * @param imgSrcConfiguration configures {@code img-src}
     * @param manifestSrcConfiguration configures {@code manifest-src}
     * @param mediaSrcConfiguration configures {@code media-src}
     * @param formActionConfiguration configures {@code form-action}
     * @param styleSrcConfiguration configures {@code style-src}
     * @param workerSrcConfiguration configures {@code worker-src}
     * @since 5.4.0
     */
    @SuppressWarnings("ParameterNumber")
    @Inject
    protected DefaultContentSecurityPolicyGenerator(ContentSecurityPolicyConfiguration cspConfiguration,
                                                    BaseUriConfiguration baseUriConfiguration,
                                                    DefaultSrcConfiguration defaultSrcConfiguration,
                                                    ConnectSrcConfiguration connectSrcConfiguration,
                                                    FencedFrameSrcConfiguration fencedFrameSrcConfiguration,
                                                    FontSrcConfiguration fontSrcConfiguration,
                                                    ObjectSrcConfiguration objectSrcConfiguration,
                                                    PrefetchSrcConfiguration prefetchSrcConfiguration,
                                                    ReportToConfiguration reportToConfiguration,
                                                    ScriptSrcConfiguration scriptSrcConfiguration,
                                                    FrameAncestorsConfiguration frameAncestorsConfiguration,
                                                    FrameSrcConfiguration frameSrcConfiguration,
                                                    ImgSrcConfiguration imgSrcConfiguration,
                                                    ManifestSrcConfiguration manifestSrcConfiguration,
                                                    MediaSrcConfiguration mediaSrcConfiguration,
                                                    FormActionConfiguration formActionConfiguration,
                                                    StyleSrcConfiguration styleSrcConfiguration,
                                                    WorkerSrcConfiguration workerSrcConfiguration) {

        this(cspConfiguration,
            req -> req.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, String.class).orElse(null),
            baseUriConfiguration,
            defaultSrcConfiguration,
            connectSrcConfiguration,
            fencedFrameSrcConfiguration,
            fontSrcConfiguration,
            objectSrcConfiguration,
            prefetchSrcConfiguration,
            reportToConfiguration,
            scriptSrcConfiguration,
            frameAncestorsConfiguration,
            frameSrcConfiguration,
            imgSrcConfiguration,
            manifestSrcConfiguration,
            mediaSrcConfiguration,
            formActionConfiguration,
            styleSrcConfiguration,
            workerSrcConfiguration);
    }

    /**
     * Creates a default policy generator with a request-aware nonce provider.
     *
     * @param cspConfiguration configures the static policy directives
     * @param cspNonceProvider CSP Nonce Provider
     * @param baseUriConfiguration configures {@code base-uri}
     * @param defaultSrcConfiguration configures {@code default-src}
     * @param connectSrcConfiguration configures {@code connect-src}
     * @param fencedFrameSrcConfiguration configures {@code fenced-frame-src}
     * @param fontSrcConfiguration configures {@code font-src}
     * @param objectSrcConfiguration configures {@code object-src}
     * @param prefetchSrcConfiguration configures {@code prefetch-src}
     * @param reportToConfiguration configures {@code report-to}
     * @param scriptSrcConfiguration configures {@code script-src}
     * @param frameAncestorsConfiguration configures {@code frame-ancestors}
     * @param frameSrcConfiguration configures {@code frame-src}
     * @param imgSrcConfiguration configures {@code img-src}
     * @param manifestSrcConfiguration configures {@code manifest-src}
     * @param mediaSrcConfiguration configures {@code media-src}
     * @param formActionConfiguration configures {@code form-action}
     * @param styleSrcConfiguration configures {@code style-src}
     * @param workerSrcConfiguration configures {@code worker-src}
     * @since 5.4.0
     */
    @SuppressWarnings("ParameterNumber")
    protected DefaultContentSecurityPolicyGenerator(ContentSecurityPolicyConfiguration cspConfiguration,
                                                    Function<HttpRequest<?>, @Nullable String> cspNonceProvider,
                                                    BaseUriConfiguration baseUriConfiguration,
                                                    DefaultSrcConfiguration defaultSrcConfiguration,
                                                    ConnectSrcConfiguration connectSrcConfiguration,
                                                    FencedFrameSrcConfiguration fencedFrameSrcConfiguration,
                                                    FontSrcConfiguration fontSrcConfiguration,
                                                    ObjectSrcConfiguration objectSrcConfiguration,
                                                    PrefetchSrcConfiguration prefetchSrcConfiguration,
                                                    ReportToConfiguration reportToConfiguration,
                                                    ScriptSrcConfiguration scriptSrcConfiguration,
                                                    FrameAncestorsConfiguration frameAncestorsConfiguration,
                                                    FrameSrcConfiguration frameSrcConfiguration,
                                                    ImgSrcConfiguration imgSrcConfiguration,
                                                    ManifestSrcConfiguration manifestSrcConfiguration,
                                                    MediaSrcConfiguration mediaSrcConfiguration,
                                                    FormActionConfiguration formActionConfiguration,
                                                    StyleSrcConfiguration styleSrcConfiguration,
                                                    WorkerSrcConfiguration workerSrcConfiguration) {
        this.cspConfiguration = cspConfiguration;
        this.cspNonceProvider = cspNonceProvider;
        this.baseUriConfiguration = baseUriConfiguration;
        this.defaultSrcConfiguration = defaultSrcConfiguration;
        this.connectSrcConfiguration = connectSrcConfiguration;
        this.fencedFrameSrcConfiguration = fencedFrameSrcConfiguration;
        this.fontSrcConfiguration = fontSrcConfiguration;
        this.objectSrcConfiguration = objectSrcConfiguration;
        this.prefetchSrcConfiguration = prefetchSrcConfiguration;
        this.reportToConfiguration = reportToConfiguration;
        this.scriptSrcConfiguration = scriptSrcConfiguration;
        this.frameAncestorsConfiguration = frameAncestorsConfiguration;
        this.frameSrcConfiguration = frameSrcConfiguration;
        this.imgSrcConfiguration = imgSrcConfiguration;
        this.manifestSrcConfiguration = manifestSrcConfiguration;
        this.mediaSrcConfiguration = mediaSrcConfiguration;
        this.formActionConfiguration = formActionConfiguration;
        this.styleSrcConfiguration = styleSrcConfiguration;
        this.workerSrcConfiguration = workerSrcConfiguration;
    }

    /**
     * Builds the complete policy for a request.
     *
     * @param request the request whose state may contribute nonce source expressions
     * @return the configured policy, or {@code null} when every directive is disabled
     */
    @Override
    public @Nullable ContentSecurityPolicy contentSecurityPolicy(HttpRequest<?> request) {
        List<ContentSecurityPolicyDirective> directives = directives(request);
        if (CollectionUtils.isEmpty(directives)) {
            return null;
        }
        return new ContentSecurityPolicy(directives);
    }

    /**
     * Generates the configured directives that do not depend on request state.
     *
     * @return the static policy directives in response-header order
     */
    protected List<ContentSecurityPolicyDirective> directives() {
        List<@Nullable ContentSecurityPolicyDirective> directives = new ArrayList<>();
        directives.add(baseUri());
        directives.add(defaultSrc());
        directives.add(connectSrc());
        directives.add(fencedFrameSrc());
        directives.add(fontSrc());
        directives.add(objectSrc());
        directives.add(prefetchSrc());
        directives.add(reportTo());
        directives.add(reportUri());
        directives.add(requireTrustedTypesFor());
        directives.add(frameAncestors());
        directives.add(frameSrc());
        directives.add(imgSrc());
        directives.add(manifestSrc());
        directives.add(mediaSrc());
        directives.add(formAction());
        directives.add(workerSrc());
        return directives.stream().filter(Objects::nonNull).toList();
    }

    /**
     * Adds request-specific nonce-capable directives to the configured baseline policy.
     *
     * <p>A nonce must be created and used within the lifetime of a single request. The same nonce
     * may therefore be added to the request's {@code style-src} and {@code script-src} directives.</p>
     *
     * @param request the request whose nonce is used to build the policy
     * @return the complete policy for the request
     */
    protected List<ContentSecurityPolicyDirective> directives(HttpRequest<?> request) {
        List<@Nullable ContentSecurityPolicyDirective> directives = new ArrayList<>(directives());
        directives.add(styleSrc(request));
        directives.add(scriptSrc(request));
        return directives.stream().filter(Objects::nonNull).toList();
    }

    /**
     * Builds the configured {@code base-uri} directive.
     *
     * @return the base URI directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable ContentSecurityPolicyDirective baseUri() {
        return directive(BASE_URI, baseUriConfiguration);
    }

    /**
     * Builds the configured {@code default-src} directive.
     *
     * @return the configured {@code default-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable ContentSecurityPolicyDirective defaultSrc() {
        return directive(DEFAULT_SRC, defaultSrcConfiguration);
    }

    /**
     * Builds the configured {@code connect-src} directive.
     *
     * @return the configured {@code connect-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable ContentSecurityPolicyDirective connectSrc() {
        return directive(CONNECT_SRC, connectSrcConfiguration);
    }

    /**
     * Builds the configured {@code fenced-frame-src} directive.
     *
     * @return the configured {@code fenced-frame-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable ContentSecurityPolicyDirective fencedFrameSrc() {
        return directive(FENCED_FRAME_SRC, fencedFrameSrcConfiguration);
    }

    /**
     * Builds the configured {@code font-src} directive.
     *
     * @return the configured {@code font-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable ContentSecurityPolicyDirective fontSrc() {
        return directive(FONT_SRC, fontSrcConfiguration);
    }

    /**
     * Builds the configured {@code object-src} directive.
     *
     * @return the configured {@code object-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable ContentSecurityPolicyDirective objectSrc() {
        return directive(OBJECT_SRC, objectSrcConfiguration);
    }

    /**
     * Builds the configured {@code prefetch-src} directive.
     *
     * @return the configured {@code prefetch-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable ContentSecurityPolicyDirective prefetchSrc() {
        return directive(PREFETCH_SRC, prefetchSrcConfiguration);
    }

    /**
     * Builds the configured {@code report-to} directive.
     *
     * @return the report-to directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable ContentSecurityPolicyDirective reportTo() {
        return reportToConfiguration.isEnabled()
            ? new ContentSecurityPolicyDirective(REPORT_TO, reportToConfiguration.getGroup())
            : null;
    }

    /**
     * Builds the configured deprecated {@code report-uri} directive.
     *
     * @return the configured deprecated {@code report-uri} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable ContentSecurityPolicyDirective reportUri() {
        return cspConfiguration.isReportUriEnabled() ? directive(REPORT_URI, cspConfiguration.getReportUri()) : null;
    }

    /**
     * Builds the configured {@code require-trusted-types-for} directive.
     *
     * @return the configured {@code require-trusted-types-for} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable ContentSecurityPolicyDirective requireTrustedTypesFor() {
        return cspConfiguration.isRequireTrustedTypesForEnabled()
                ? new ContentSecurityPolicyDirective(REQUIRE_TRUSTED_TYPES_FOR, cspConfiguration.getRequireTrustedTypesFor()) : null;
    }

    /**
     * Builds the configured {@code frame-ancestors} directive.
     *
     * @return the configured {@code frame-ancestors} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable ContentSecurityPolicyDirective frameAncestors() {
        return directive(FRAME_ANCESTORS, frameAncestorsConfiguration);
    }

    /**
     * Builds the configured {@code frame-src} directive.
     *
     * @return the configured {@code frame-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable ContentSecurityPolicyDirective frameSrc() {
        return directive(FRAME_SRC, frameSrcConfiguration);
    }

    /**
     * Builds the configured {@code img-src} directive.
     *
     * @return the configured {@code img-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable ContentSecurityPolicyDirective imgSrc() {
        return directive(IMG_SRC, imgSrcConfiguration);
    }

    /**
     * Builds the configured {@code manifest-src} directive.
     *
     * @return the configured {@code manifest-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable ContentSecurityPolicyDirective manifestSrc() {
        return directive(MANIFEST_SRC, manifestSrcConfiguration);
    }

    /**
     * Builds the configured {@code media-src} directive.
     *
     * @return the configured {@code media-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable ContentSecurityPolicyDirective mediaSrc() {
        return directive(MEDIA_SRC, mediaSrcConfiguration);
    }

    /**
     * Builds the configured {@code form-action} directive.
     *
     * @return the configured {@code form-action} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable ContentSecurityPolicyDirective formAction() {
        return directive(FORM_ACTION, formActionConfiguration);
    }

    /**
     * Builds the request-specific {@code style-src} directive.
     *
     * @param request the request whose nonce may be included in the directive
     * @return the configured {@code style-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable ContentSecurityPolicyDirective styleSrc(HttpRequest<?> request) {
        return directive(STYLE_SRC, styleSrcConfiguration, request);
    }

    /**
     * Builds the request-specific {@code script-src} directive.
     *
     * @param request the request whose nonce may be included in the directive
     * @return the configured {@code script-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable ContentSecurityPolicyDirective scriptSrc(HttpRequest<?> request) {
        return directive(SCRIPT_SRC, scriptSrcConfiguration, request);
    }

    /**
     * Builds the configured {@code worker-src} directive.
     *
     * @return the configured {@code worker-src} directive, or {@code null} when disabled
     * @since 5.4.0
     */
    protected @Nullable ContentSecurityPolicyDirective workerSrc() {
        return directive(WORKER_SRC, workerSrcConfiguration);
    }

    /**
     * Converts source expressions to CSP's space-separated directive representation.
     *
     * @param name the CSP directive name
     * @param values the source expressions associated with the directive
     * @return the serialized directive
     */
    private static ContentSecurityPolicyDirective directive(String name, List<String> values) {
        return new ContentSecurityPolicyDirective(name, String.join(SPACE, values.stream()
            .filter(StringUtils::isNotEmpty)
            .toList()));
    }

    /**
     * Converts source expressions to CSP's space-separated directive representation.
     *
     * @param name the CSP directive name
     * @param config configuration that supplies the directive values
     * @return the serialized directive
     */
    private @Nullable ContentSecurityPolicyDirective directive(String name,
                                                               DirectiveConfiguration config) {
        return directive(name, config, null);
    }

    /**
     * Converts source expressions to CSP's space-separated directive representation.
     *
     * @param name the CSP directive name
     * @param config configuration that supplies the directive values
     * @return the serialized directive
     */
    private @Nullable ContentSecurityPolicyDirective directive(String name,
                                                               DirectiveConfiguration config,
                                                               @Nullable HttpRequest<?> request) {
        if (!config.isEnabled()) {
            return null;
        }
        List<String> values = new ArrayList<>();
        if (config instanceof NonceConfiguration nonceConfiguration && nonceConfiguration.isNonce()) {
            String nonce = cspNonceProvider.apply(request);
            if (StringUtils.isNotEmpty(nonce)) {
                values.add(ContentSecurityPolicyUtils.wrapInSingleQuotes(NONCE_PREFIX + nonce));
            } else if (LOG.isTraceEnabled()) {
                LOG.trace("CSP nonce not found in request attribute {}", ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE);
            }
        }
        if (config.isSelf()) {
            values.add(ContentSecurityPolicyUtils.wrapInSingleQuotes(SELF));
        }
        if (config.isUnsafeInline()) {
            values.add(ContentSecurityPolicyUtils.wrapInSingleQuotes(UNSAFE_INLINE));
        }
        if (config.isUnsafeEval()) {
            values.add(ContentSecurityPolicyUtils.wrapInSingleQuotes(UNSAFE_EVAL));
        }
        if (config.isStrictDynamic()) {
            values.add(ContentSecurityPolicyUtils.wrapInSingleQuotes(STRICT_DYNAMIC));
        }
        if (config.isUnsafeHashes()) {
            values.add(ContentSecurityPolicyUtils.wrapInSingleQuotes("unsafe-hashes"));
        }
        if (config.isReportSample()) {
            values.add(ContentSecurityPolicyUtils.wrapInSingleQuotes("report-sample"));
        }
        if (config.isUnsafeAllowRedirects()) {
            values.add(ContentSecurityPolicyUtils.wrapInSingleQuotes("unsafe-allow-redirects"));
        }
        if (config.isWasmUnsafeEval()) {
            values.add(ContentSecurityPolicyUtils.wrapInSingleQuotes("wasm-unsafe-eval"));
        }
        if (config.isTrustedTypesEval()) {
            values.add(ContentSecurityPolicyUtils.wrapInSingleQuotes("trusted-types-eval"));
        }
        if (config.isReportSha256()) {
            values.add(ContentSecurityPolicyUtils.wrapInSingleQuotes("report-sha256"));
        }
        if (config.isReportSha384()) {
            values.add(ContentSecurityPolicyUtils.wrapInSingleQuotes("report-sha384"));
        }
        if (config.isReportSha512()) {
            values.add(ContentSecurityPolicyUtils.wrapInSingleQuotes("report-sha512"));
        }
        if (config.isUnsafeWebtransportHashes()) {
            values.add(ContentSecurityPolicyUtils.wrapInSingleQuotes("unsafe-webtransport-hashes"));
        }
        ContentSecurityPolicyUtils.addSchemeSources(config, values);
        if (config instanceof SourceListDirectiveConfiguration sourceListDirectiveConfiguration) {
            values.addAll(sourceListDirectiveConfiguration.getValues());
        }
        if (config instanceof ScriptSrcConfiguration scriptSrcConfiguration) {
            values.addAll(scriptSrcConfiguration.getUrls());
        }
        values.removeIf(StringUtils::isEmpty);
        if (config.isNone() && values.isEmpty()) {
            values.add(ContentSecurityPolicyUtils.wrapInSingleQuotes(NONE));
        }
        if (values.isEmpty()) {
            return null;
        }
        return new ContentSecurityPolicyDirective(name, String.join(SPACE, values.stream()
            .filter(StringUtils::isNotEmpty)
            .toList()));
    }
}
