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
import java.util.function.Function;

import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.HTTP;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.HTTPS;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.NONCE_PREFIX;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.SCRIPT_SRC;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.SELF;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.SPACE;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.STRICT_DYNAMIC;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.UNSAFE_EVAL;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.UNSAFE_INLINE;

/**
 * Generates the module's nonce-based {@code script-src} directive.
 *
 * <p>Configured keywords and hash expressions are quoted, while scheme and URL sources retain
 * their CSP-required unquoted representation. Applications can replace this bean with a custom
 * {@link ScriptSrcGenerator} when they need a different script policy.</p>
 *
 * @since 5.4.0
 */
@Singleton
public class DefaultScriptSrcGenerator implements ScriptSrcGenerator {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultScriptSrcGenerator.class);

    private final ContentSecurityPolicyConfiguration cspConfiguration;
    private final Function<HttpRequest<?>, @Nullable String> cspNonceProvider;

    /**
     * Creates a generator that reads the nonce stored by the CSP server filter.
     *
     * @param cspConfiguration configures the generated script policy
     * @since 5.4.0
     */
    @Inject
    public DefaultScriptSrcGenerator(ContentSecurityPolicyConfiguration cspConfiguration) {
        this(cspConfiguration, req -> req.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, String.class).orElse(null));
    }

    /**
     * Creates a generator with a custom request-to-nonce lookup.
     *
     * <p>This constructor supports subclassing and testing; production applications normally use
     * {@link #DefaultScriptSrcGenerator(ContentSecurityPolicyConfiguration)}.</p>
     *
     * @param cspConfiguration configures the generated script policy
     * @param cspNonceProvider obtains the request nonce, or {@code null} when none is available
     * @since 5.4.0
     */
    public DefaultScriptSrcGenerator(ContentSecurityPolicyConfiguration cspConfiguration,
                                     Function<HttpRequest<?>, @Nullable String> cspNonceProvider) {
        this.cspConfiguration = cspConfiguration;
        this.cspNonceProvider = cspNonceProvider;
    }

    /**
     * Builds the nonce- and strict-dynamic-based {@code script-src} directive when either option is enabled.
     *
     * @param request the request from which to obtain the CSP nonce
     * @return the script directive, or {@code null} if it has no configured values
     * @since 5.4.0
     */
    @Override
    public @Nullable ContentSecurityPolicyDirective generateScriptSrcDirective(HttpRequest<?> request) {
        List<String> values = new ArrayList<>();
        if (cspConfiguration.isScriptSrcNonceEnabled()) {
            String nonce = cspNonceProvider.apply(request);
            if (StringUtils.isNotEmpty(nonce)) {
                values.add(NONCE_PREFIX + nonce);
            } else {
                if (LOG.isTraceEnabled()) {
                    LOG.trace("CSP nonce not found in request attribute {}", ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE);
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
            values = new ArrayList<>(values.stream()
                .map(ContentSecurityPolicyUtils::wrapInSingleQuotes)
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
            : new ContentSecurityPolicyDirective(SCRIPT_SRC, String.join(SPACE, values));
    }
}
