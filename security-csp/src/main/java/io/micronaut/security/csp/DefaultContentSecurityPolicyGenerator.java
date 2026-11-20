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
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.util.CollectionUtils;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.csp.conf.NonceConfiguration;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfiguration;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties;
import io.micronaut.security.csp.conf.ContentSecurityPolicyDirectiveConfigurations;
import io.micronaut.security.csp.conf.DirectiveConfiguration;
import io.micronaut.security.csp.conf.SourceListDirectiveConfiguration;
import io.micronaut.security.csp.conf.reportto.ReportToConfigurationProperties;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
 * @since 5.6.0
 */
@Requires(missingBeans = ContentSecurityPolicyGenerator.class)
@Singleton
public class DefaultContentSecurityPolicyGenerator implements ContentSecurityPolicyGenerator {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultContentSecurityPolicyGenerator.class);
    private static final String PROPERTY_PREFIX = ContentSecurityPolicyConfigurationProperties.PREFIX + ".";
    private static final String PROPERTY_REPORT_URI = PROPERTY_PREFIX + REPORT_URI;
    private static final String PROPERTY_REQUIRE_TRUSTED_TYPES_FOR = PROPERTY_PREFIX + REQUIRE_TRUSTED_TYPES_FOR;
    private static final String PROPERTY_REPORT_TO_GROUP = ReportToConfigurationProperties.PREFIX + ".group";
    /**
     * Keyword source expressions, in the order in which they are emitted, with the configuration
     * flag that enables each of them.
     */
    private static final List<FlaggedSource> KEYWORD_SOURCES = List.of(
        new FlaggedSource(SELF, DirectiveConfiguration::isSelf),
        new FlaggedSource(UNSAFE_INLINE, DirectiveConfiguration::isUnsafeInline),
        new FlaggedSource(UNSAFE_EVAL, DirectiveConfiguration::isUnsafeEval),
        new FlaggedSource(STRICT_DYNAMIC, DirectiveConfiguration::isStrictDynamic),
        new FlaggedSource("unsafe-hashes", DirectiveConfiguration::isUnsafeHashes),
        new FlaggedSource("report-sample", DirectiveConfiguration::isReportSample),
        new FlaggedSource("wasm-unsafe-eval", DirectiveConfiguration::isWasmUnsafeEval),
        new FlaggedSource("trusted-types-eval", DirectiveConfiguration::isTrustedTypesEval),
        new FlaggedSource("report-sha256", DirectiveConfiguration::isReportSha256),
        new FlaggedSource("report-sha384", DirectiveConfiguration::isReportSha384),
        new FlaggedSource("report-sha512", DirectiveConfiguration::isReportSha512),
        new FlaggedSource("unsafe-webtransport-hashes", DirectiveConfiguration::isUnsafeWebtransportHashes)
    );
    /**
     * Scheme source expressions, in the order in which they are emitted, with the configuration
     * flag that enables each of them.
     */
    private static final List<FlaggedSource> SCHEME_SOURCES = List.of(
        new FlaggedSource(HTTP, DirectiveConfiguration::isHttp),
        new FlaggedSource(HTTPS, DirectiveConfiguration::isHttps),
        new FlaggedSource(DATA, DirectiveConfiguration::isData),
        new FlaggedSource(BLOB, DirectiveConfiguration::isBlob),
        new FlaggedSource(FILESYSTEM, DirectiveConfiguration::isFilesystem),
        new FlaggedSource(MEDIASTREAM, DirectiveConfiguration::isMediastream),
        new FlaggedSource(WS, DirectiveConfiguration::isWs),
        new FlaggedSource(WSS, DirectiveConfiguration::isWss)
    );
    /**
     * Keywords that are only meaningful when single-quoted. Unquoted, a browser reads them as host
     * sources. They are the emitted keyword sources plus {@code none}.
     */
    private static final Set<String> QUOTED_KEYWORDS = Stream.concat(Stream.of(NONE), KEYWORD_SOURCES.stream().map(FlaggedSource::expression))
        .collect(Collectors.toUnmodifiableSet());
    /**
     * Prefixes of hash and nonce source expressions, which are only meaningful when single-quoted.
     */
    private static final List<String> QUOTED_PREFIXES = List.of("sha256-", "sha384-", "sha512-", NONCE_PREFIX);
    /**
     * Characters that end a directive ({@code ;}), a policy ({@code ,}) or the header (control characters).
     */
    private static final Pattern UNSAFE_HEADER_CHARACTERS = Pattern.compile("[;,\\p{Cntrl}]");
    /**
     * The grammar of a Reporting API endpoint group name used by {@code report-to}.
     */
    private static final Pattern REPORTING_GROUP_GRAMMAR = Pattern.compile("[a-z*][a-z0-9_.*-]*");
    private static final Set<String> LOOPBACK_HOSTS = Set.of("localhost", "127.0.0.1", "[::1]");
    /**
     * The CSP {@code base64-value} grammar for nonces. A value outside it, for example one with a
     * quote, semicolon or space, would corrupt or extend the serialized policy.
     */
    private static final Pattern NONCE_GRAMMAR = Pattern.compile("[A-Za-z0-9+/_-]+={0,2}");
    /**
     * The configuration behind each directive that is built from a {@link DirectiveConfiguration}.
     * It is the only place that pairs a directive name with its configuration: both the startup
     * validation of the configured values and the directive methods read it, so a directive cannot
     * be emitted without being validated.
     */
    private static final Map<String, Function<ContentSecurityPolicyDirectiveConfigurations, DirectiveConfiguration>> DIRECTIVE_CONFIGURATIONS = directiveConfigurationGetters();
    private final ContentSecurityPolicyConfiguration cspConfiguration;
    private final ContentSecurityPolicyDirectiveConfigurations directiveConfigurations;
    private final Function<HttpRequest<?>, @Nullable String> cspNonceProvider;
    private final AtomicBoolean invalidNonceWarned = new AtomicBoolean();

    /**
     * Creates a default policy generator from the root and directive-specific configuration.
     *
     * @param cspConfiguration configures the static policy directives
     * @param directiveConfigurations configures each directive that has its own configuration
     * @since 5.6.0
     */
    @Inject
    protected DefaultContentSecurityPolicyGenerator(ContentSecurityPolicyConfiguration cspConfiguration,
                                                    ContentSecurityPolicyDirectiveConfigurations directiveConfigurations) {
        this(cspConfiguration, DefaultContentSecurityPolicyGenerator::requestNonce, directiveConfigurations);
    }

    /**
     * Creates a default policy generator with a request-aware nonce provider.
     *
     * @param cspConfiguration configures the static policy directives
     * @param cspNonceProvider CSP Nonce Provider
     * @param directiveConfigurations configures each directive that has its own configuration
     * @since 5.6.0
     */
    protected DefaultContentSecurityPolicyGenerator(ContentSecurityPolicyConfiguration cspConfiguration,
                                                    Function<HttpRequest<?>, @Nullable String> cspNonceProvider,
                                                    ContentSecurityPolicyDirectiveConfigurations directiveConfigurations) {
        this.cspConfiguration = cspConfiguration;
        if (cspConfiguration.isReportUriEnabled() && reportUris(cspConfiguration).isEmpty()) {
            LOG.warn("CSP report-uri is enabled but no report URIs are configured; the report-uri directive is omitted");
        }
        this.cspNonceProvider = cspNonceProvider;
        this.directiveConfigurations = directiveConfigurations;
        validateRootConfiguration();
        validateSourceExpressions();
    }

    /**
     * Rejects root and {@code report-to} settings that would corrupt or extend the serialized policy.
     *
     * @throws ConfigurationException if a setting contains a character that ends a directive or policy
     */
    private void validateRootConfiguration() {
        if (cspConfiguration.isReportUriEnabled()) {
            for (String reportUri : cspConfiguration.getReportUri()) {
                requireSafeHeaderValue(PROPERTY_REPORT_URI, reportUri);
                warnIfPlaintext(reportUri);
            }
        }
        if (cspConfiguration.isRequireTrustedTypesForEnabled()) {
            requireSafeHeaderValue(PROPERTY_REQUIRE_TRUSTED_TYPES_FOR, cspConfiguration.getRequireTrustedTypesFor());
        }
        if (directiveConfigurations.getReportTo().isEnabled() && !REPORTING_GROUP_GRAMMAR.matcher(directiveConfigurations.getReportTo().getGroup()).matches()) {
            throw new ConfigurationException(PROPERTY_REPORT_TO_GROUP + " must match " + REPORTING_GROUP_GRAMMAR.pattern()
                + ", the grammar of a Reporting-Endpoints name");
        }
    }

    /**
     * Warns about a plaintext {@code http:} report URI on a non-loopback host, because violation
     * reports carry document URLs, referrers and samples that may contain sensitive data.
     *
     * @param reportUri a configured {@code report-uri} endpoint
     */
    private static void warnIfPlaintext(String reportUri) {
        String trimmed = reportUri.trim();
        if (!trimmed.regionMatches(true, 0, "http://", 0, "http://".length())) {
            return;
        }
        String host;
        try {
            host = URI.create(trimmed).getHost();
        } catch (IllegalArgumentException e) {
            host = null;
        }
        if (host == null || !LOOPBACK_HOSTS.contains(host.toLowerCase(Locale.ROOT))) {
            LOG.warn("{} contains the plaintext endpoint {}; violation reports can contain sensitive URLs. Use https.",
                PROPERTY_REPORT_URI, trimmed);
        }
    }

    /**
     * Fails closed when a configured value contains a semicolon, comma or control character, which
     * would end the directive or policy, or break the header.
     *
     * @param property the configuration property that supplies the value
     * @param value the configured value
     * @throws ConfigurationException if the value is unsafe
     */
    private static void requireSafeHeaderValue(String property, String value) {
        if (UNSAFE_HEADER_CHARACTERS.matcher(value).find()) {
            throw new ConfigurationException(property + " contains a ';', ',' or control character, which would end the directive "
                + "or policy. Configure each source expression as a separate value.");
        }
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
     * @since 5.6.0
     */
    protected @Nullable ContentSecurityPolicyDirective baseUri() {
        return directive(BASE_URI, null);
    }

    /**
     * Builds the configured {@code default-src} directive.
     *
     * @return the configured {@code default-src} directive, or {@code null} when disabled
     * @since 5.6.0
     */
    protected @Nullable ContentSecurityPolicyDirective defaultSrc() {
        return directive(DEFAULT_SRC, null);
    }

    /**
     * Builds the configured {@code connect-src} directive.
     *
     * @return the configured {@code connect-src} directive, or {@code null} when disabled
     * @since 5.6.0
     */
    protected @Nullable ContentSecurityPolicyDirective connectSrc() {
        return directive(CONNECT_SRC, null);
    }

    /**
     * Builds the configured {@code fenced-frame-src} directive.
     *
     * @return the configured {@code fenced-frame-src} directive, or {@code null} when disabled
     * @since 5.6.0
     */
    protected @Nullable ContentSecurityPolicyDirective fencedFrameSrc() {
        return directive(FENCED_FRAME_SRC, null);
    }

    /**
     * Builds the configured {@code font-src} directive.
     *
     * @return the configured {@code font-src} directive, or {@code null} when disabled
     * @since 5.6.0
     */
    protected @Nullable ContentSecurityPolicyDirective fontSrc() {
        return directive(FONT_SRC, null);
    }

    /**
     * Builds the configured {@code object-src} directive.
     *
     * @return the configured {@code object-src} directive, or {@code null} when disabled
     * @since 5.6.0
     */
    protected @Nullable ContentSecurityPolicyDirective objectSrc() {
        return directive(OBJECT_SRC, null);
    }

    /**
     * Builds the configured {@code prefetch-src} directive.
     *
     * @return the configured {@code prefetch-src} directive, or {@code null} when disabled
     * @since 5.6.0
     */
    protected @Nullable ContentSecurityPolicyDirective prefetchSrc() {
        return directive(PREFETCH_SRC, null);
    }

    /**
     * Builds the configured {@code report-to} directive.
     *
     * @return the report-to directive, or {@code null} when disabled
     * @since 5.6.0
     */
    protected @Nullable ContentSecurityPolicyDirective reportTo() {
        return directiveConfigurations.getReportTo().isEnabled()
            ? new ContentSecurityPolicyDirective(REPORT_TO, directiveConfigurations.getReportTo().getGroup())
            : null;
    }

    /**
     * Builds the configured deprecated {@code report-uri} directive.
     *
     * @return the configured deprecated {@code report-uri} directive, or {@code null} when disabled
     * @since 5.6.0
     */
    protected @Nullable ContentSecurityPolicyDirective reportUri() {
        if (!cspConfiguration.isReportUriEnabled()) {
            return null;
        }
        List<String> reportUris = reportUris(cspConfiguration);
        return reportUris.isEmpty() ? null : new ContentSecurityPolicyDirective(REPORT_URI, String.join(SPACE, reportUris));
    }

    /**
     * Builds the configured {@code require-trusted-types-for} directive.
     *
     * @return the configured {@code require-trusted-types-for} directive, or {@code null} when disabled
     * @since 5.6.0
     */
    protected @Nullable ContentSecurityPolicyDirective requireTrustedTypesFor() {
        return cspConfiguration.isRequireTrustedTypesForEnabled()
                ? new ContentSecurityPolicyDirective(REQUIRE_TRUSTED_TYPES_FOR, cspConfiguration.getRequireTrustedTypesFor()) : null;
    }

    /**
     * Builds the configured {@code frame-ancestors} directive.
     *
     * @return the configured {@code frame-ancestors} directive, or {@code null} when disabled
     * @since 5.6.0
     */
    protected @Nullable ContentSecurityPolicyDirective frameAncestors() {
        return directive(FRAME_ANCESTORS, null);
    }

    /**
     * Builds the configured {@code frame-src} directive.
     *
     * @return the configured {@code frame-src} directive, or {@code null} when disabled
     * @since 5.6.0
     */
    protected @Nullable ContentSecurityPolicyDirective frameSrc() {
        return directive(FRAME_SRC, null);
    }

    /**
     * Builds the configured {@code img-src} directive.
     *
     * @return the configured {@code img-src} directive, or {@code null} when disabled
     * @since 5.6.0
     */
    protected @Nullable ContentSecurityPolicyDirective imgSrc() {
        return directive(IMG_SRC, null);
    }

    /**
     * Builds the configured {@code manifest-src} directive.
     *
     * @return the configured {@code manifest-src} directive, or {@code null} when disabled
     * @since 5.6.0
     */
    protected @Nullable ContentSecurityPolicyDirective manifestSrc() {
        return directive(MANIFEST_SRC, null);
    }

    /**
     * Builds the configured {@code media-src} directive.
     *
     * @return the configured {@code media-src} directive, or {@code null} when disabled
     * @since 5.6.0
     */
    protected @Nullable ContentSecurityPolicyDirective mediaSrc() {
        return directive(MEDIA_SRC, null);
    }

    /**
     * Builds the configured {@code form-action} directive.
     *
     * @return the configured {@code form-action} directive, or {@code null} when disabled
     * @since 5.6.0
     */
    protected @Nullable ContentSecurityPolicyDirective formAction() {
        return directive(FORM_ACTION, null);
    }

    /**
     * Builds the request-specific {@code style-src} directive.
     *
     * @param request the request whose nonce may be included in the directive
     * @return the configured {@code style-src} directive, or {@code null} when disabled
     * @since 5.6.0
     */
    protected @Nullable ContentSecurityPolicyDirective styleSrc(HttpRequest<?> request) {
        return directive(STYLE_SRC, request);
    }

    /**
     * Builds the request-specific {@code script-src} directive.
     *
     * @param request the request whose nonce may be included in the directive
     * @return the configured {@code script-src} directive, or {@code null} when disabled
     * @since 5.6.0
     */
    protected @Nullable ContentSecurityPolicyDirective scriptSrc(HttpRequest<?> request) {
        return directive(SCRIPT_SRC, request);
    }

    /**
     * Builds the configured {@code worker-src} directive.
     *
     * @return the configured {@code worker-src} directive, or {@code null} when disabled
     * @since 5.6.0
     */
    protected @Nullable ContentSecurityPolicyDirective workerSrc() {
        return directive(WORKER_SRC, null);
    }

    /**
     * Returns the configured {@code report-uri} endpoints, without blank entries.
     *
     * @param cspConfiguration root CSP configuration
     * @return the non-blank report URIs
     */
    private static List<String> reportUris(ContentSecurityPolicyConfiguration cspConfiguration) {
        return cspConfiguration.getReportUri().stream()
            .filter(StringUtils::isNotEmpty)
            .toList();
    }

    /**
     * Validates the configured source expressions: a value containing a semicolon, comma or control
     * character fails startup, and an unquoted keyword, hash or nonce, which a browser reads as a
     * host source, is logged as a warning.
     */
    private void validateSourceExpressions() {
        DIRECTIVE_CONFIGURATIONS.forEach((name, getter) -> {
            DirectiveConfiguration configuration = getter.apply(directiveConfigurations);
            if (configuration.isEnabled() && configuration instanceof SourceListDirectiveConfiguration sourceList) {
                for (String value : sourceList.getValues()) {
                    validateSourceExpression(name, value);
                }
            }
        });
    }

    private static void validateSourceExpression(String directive, String value) {
        String property = PROPERTY_PREFIX + directive + ".values";
        requireSafeHeaderValue(property, value);
        String trimmed = value.trim();
        if (trimmed.startsWith(SINGLE_QUOTE)) {
            return;
        }
        String lowerCase = trimmed.toLowerCase(Locale.ROOT);
        if (QUOTED_KEYWORDS.contains(lowerCase) || QUOTED_PREFIXES.stream().anyMatch(lowerCase::startsWith)) {
            LOG.warn("{} contains \"{}\", which looks like a keyword, hash or nonce source but is not single-quoted; "
                + "browsers treat it as a host. Use \"{}\".", property, value, ContentSecurityPolicyUtils.wrapInSingleQuotes(trimmed));
        }
    }

    /**
     * Reads the nonce generated for the request by the CSP server filter.
     *
     * @param request the current request
     * @return the request nonce, or {@code null} when none was generated
     */
    private static @Nullable String requestNonce(HttpRequest<?> request) {
        return request.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, String.class).orElse(null);
    }

    private static Map<String, Function<ContentSecurityPolicyDirectiveConfigurations, DirectiveConfiguration>> directiveConfigurationGetters() {
        Map<String, Function<ContentSecurityPolicyDirectiveConfigurations, DirectiveConfiguration>> getters = new LinkedHashMap<>();
        getters.put(BASE_URI, ContentSecurityPolicyDirectiveConfigurations::getBaseUri);
        getters.put(DEFAULT_SRC, ContentSecurityPolicyDirectiveConfigurations::getDefaultSrc);
        getters.put(CONNECT_SRC, ContentSecurityPolicyDirectiveConfigurations::getConnectSrc);
        getters.put(FENCED_FRAME_SRC, ContentSecurityPolicyDirectiveConfigurations::getFencedFrameSrc);
        getters.put(FONT_SRC, ContentSecurityPolicyDirectiveConfigurations::getFontSrc);
        getters.put(OBJECT_SRC, ContentSecurityPolicyDirectiveConfigurations::getObjectSrc);
        getters.put(PREFETCH_SRC, ContentSecurityPolicyDirectiveConfigurations::getPrefetchSrc);
        getters.put(SCRIPT_SRC, ContentSecurityPolicyDirectiveConfigurations::getScriptSrc);
        getters.put(FRAME_ANCESTORS, ContentSecurityPolicyDirectiveConfigurations::getFrameAncestors);
        getters.put(FRAME_SRC, ContentSecurityPolicyDirectiveConfigurations::getFrameSrc);
        getters.put(IMG_SRC, ContentSecurityPolicyDirectiveConfigurations::getImgSrc);
        getters.put(MANIFEST_SRC, ContentSecurityPolicyDirectiveConfigurations::getManifestSrc);
        getters.put(MEDIA_SRC, ContentSecurityPolicyDirectiveConfigurations::getMediaSrc);
        getters.put(FORM_ACTION, ContentSecurityPolicyDirectiveConfigurations::getFormAction);
        getters.put(STYLE_SRC, ContentSecurityPolicyDirectiveConfigurations::getStyleSrc);
        getters.put(WORKER_SRC, ContentSecurityPolicyDirectiveConfigurations::getWorkerSrc);
        return getters;
    }

    /**
     * Builds a directive from the configuration registered for it in {@link #DIRECTIVE_CONFIGURATIONS}.
     *
     * @param name the CSP directive name
     * @param request the request whose nonce may be added, or {@code null} for request-independent directives
     * @return the directive, or {@code null} when it is disabled or has no source expressions
     * @throws IllegalStateException if no configuration is registered for the directive
     */
    private @Nullable ContentSecurityPolicyDirective directive(String name, @Nullable HttpRequest<?> request) {
        Function<ContentSecurityPolicyDirectiveConfigurations, DirectiveConfiguration> getter = DIRECTIVE_CONFIGURATIONS.get(name);
        if (getter == null) {
            throw new IllegalStateException("No configuration is registered for the CSP directive " + name);
        }
        return directive(name, getter.apply(directiveConfigurations), request);
    }

    /**
     * Converts the enabled source expressions of a directive configuration to CSP's
     * space-separated directive representation.
     *
     * <p>Expressions are emitted in this order: the request nonce, keyword sources in
     * {@link #KEYWORD_SOURCES} order, scheme sources, and finally the configured values.
     * {@code 'none'} is emitted only when no other expression is enabled.</p>
     *
     * @param name the CSP directive name
     * @param config configuration that supplies the directive values
     * @param request the request whose nonce may be added, or {@code null} for request-independent directives
     * @return the directive, or {@code null} when it is disabled or has no source expressions
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
            if (StringUtils.isNotEmpty(nonce) && NONCE_GRAMMAR.matcher(nonce).matches()) {
                values.add(ContentSecurityPolicyUtils.wrapInSingleQuotes(NONCE_PREFIX + nonce));
            } else if (StringUtils.isNotEmpty(nonce)) {
                // The nonce is not logged: it is a secret for the current response.
                if (invalidNonceWarned.compareAndSet(false, true)) {
                    LOG.warn("Omitting the CSP nonce from {}: the ContentSecurityPolicyNonceGenerator bean returned a value with characters outside "
                        + "base64 and base64url (A-Z, a-z, 0-9, +, /, _, - and trailing =). Return a base64 or base64url value. "
                        + "This warning is logged once.", name);
                }
            } else if (LOG.isTraceEnabled()) {
                LOG.trace("CSP nonce not found in request attribute {}", ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE);
            }
        }
        for (FlaggedSource keywordSource : KEYWORD_SOURCES) {
            if (keywordSource.enabled().test(config)) {
                values.add(ContentSecurityPolicyUtils.wrapInSingleQuotes(keywordSource.expression()));
            }
        }
        for (FlaggedSource schemeSource : SCHEME_SOURCES) {
            if (schemeSource.enabled().test(config)) {
                values.add(schemeSource.expression());
            }
        }
        if (config instanceof SourceListDirectiveConfiguration sourceListDirectiveConfiguration) {
            values.addAll(sourceListDirectiveConfiguration.getValues());
        }
        values.removeIf(StringUtils::isEmpty);
        if (config.isNone() && values.isEmpty()) {
            values.add(ContentSecurityPolicyUtils.wrapInSingleQuotes(NONE));
        }
        if (values.isEmpty()) {
            return null;
        }
        return new ContentSecurityPolicyDirective(name, String.join(SPACE, values));
    }

    /**
     * A keyword or scheme source expression and the configuration flag that enables it.
     *
     * @param expression the source expression; a keyword without its surrounding quotes
     * @param enabled tests whether a directive configuration enables the expression
     */
    private record FlaggedSource(String expression, Predicate<DirectiveConfiguration> enabled) {
    }
}
