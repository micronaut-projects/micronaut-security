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
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.logging.LogLevel;
import jakarta.inject.Inject;
import jakarta.inject.Provider;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

@Requires(missingBeans = ContentSecurityPolicyGenerator.class)
@Singleton
@Internal
final class DefaultContentSecurityPolicyGenerator implements ContentSecurityPolicyGenerator {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultContentSecurityPolicyGenerator.class);
    private final ContentSecurityPolicyConfiguration cspConfiguration;
    private final Function<HttpRequest<?>, String> cspNonceProvider;

    /**
     * @param cspConfiguration configures the generated default policy
     */
    @Inject
    DefaultContentSecurityPolicyGenerator(ContentSecurityPolicyConfiguration cspConfiguration) {
        this(cspConfiguration, req -> req.getAttribute(CspNonceGenerator.CSP_NONCE_ATTRIBUTE, String.class).orElse(null));
    }
    /**
     * @param cspConfiguration configures the generated default policy
     * @param cspNonceProvider generates and stores the request CSP nonce
     */
    DefaultContentSecurityPolicyGenerator(ContentSecurityPolicyConfiguration cspConfiguration,
                                          Function<HttpRequest<?>, @Nullable String> cspNonceProvider) {
        this.cspConfiguration = cspConfiguration;
        this.cspNonceProvider = cspNonceProvider;
    }

    @Override
    public List<CspDirective> contentSecurityPolicy() {
        List<CspDirective> directives = new ArrayList<>();
        if (cspConfiguration.isBaseUriEnabled()) {
            directives.add(directive(BASE_URI, cspConfiguration.getBaseUri()));
        }
        if (cspConfiguration.isConnectSrcEnabled()) {
            directives.add(directive(CONNECT_SRC, cspConfiguration.getConnectSrc()));
        }
        if (cspConfiguration.isFontSrcEnabled()) {
            directives.add(directive(FONT_SRC, cspConfiguration.getFontSrc()));
        }
        if (cspConfiguration.isObjectSrcEnabled()) {
            directives.add(directive(OBJECT_SRC, cspConfiguration.getObjectSrc()));
        }
        if (cspConfiguration.isPrefetchSrcEnabled()) {
            directives.add(directive(PREFETCH_SRC, cspConfiguration.getPrefetchSrc()));
        }
        if (cspConfiguration.isRequireTrustedTypesForEnabled()) {
            directives.add(new CspDirective(REQUIRE_TRUSTED_TYPES_FOR, cspConfiguration.getRequireTrustedTypesFor()));
        }
        if (cspConfiguration.isFrameAncestorsEnabled()) {
            directives.add(directive(FRAME_ANCESTORS, cspConfiguration.getFrameAncestors()));
        }
        if (cspConfiguration.isFrameSrcEnabled()) {
            directives.add(directive(FRAME_SRC, cspConfiguration.getFrameSrc()));
        }
        if (cspConfiguration.isImgSrcEnabled()) {
            directives.add(directive(IMG_SRC, cspConfiguration.getImgSrc()));
        }
        if (cspConfiguration.isManifestSrcEnabled()) {
            directives.add(directive(MANIFEST_SRC, cspConfiguration.getManifestSrc()));
        }
        if (cspConfiguration.isMediaSrcEnabled()) {
            directives.add(directive(MEDIA_SRC, cspConfiguration.getMediaSrc()));
        }
        if (cspConfiguration.isFormActionEnabled()) {
            directives.add(directive(FORM_ACTION, cspConfiguration.getFormAction()));
        }
        if (cspConfiguration.isStyleSrcEnabled()) {
            directives.add(directive(STYLE_SRC, cspConfiguration.getStyleSrc()));
        }
        if (cspConfiguration.isWorkerSrcEnabled()) {
            directives.add(directive(WORKER_SRC, cspConfiguration.getWorkerSrc()));
        }
        return directives;
    }

    @Override
    public List<CspDirective> contentSecurityPolicy(HttpRequest<?> request) {
        List<CspDirective> directives = new ArrayList<>(contentSecurityPolicy());
        CspDirective scriptSrc = scriptSrc(request);
        if (scriptSrc != null) {
            directives.add(scriptSrc);
        }
        return directives;
    }

    protected @Nullable CspDirective scriptSrc(HttpRequest<?> request) {
        List<String> values = new ArrayList<>();
        if (cspConfiguration.isScriptSrcNonceEnabled()) {
            String nonce = cspNonceProvider.apply(request);
            if (StringUtils.isNotEmpty(nonce)) {
                values.add("'nonce-" + nonce + "'");
            } else {
                if (LOG.isTraceEnabled()) {
                    LOG.trace("CSP nonce not found in request attribute {}", CspNonceGenerator.CSP_NONCE_ATTRIBUTE);
                }
            }
        }
        if (cspConfiguration.isScriptSrcStrictDynamic()) {
            values.add("'" + STRICT_DYNAMIC + "'");
        }
        return values.isEmpty()
                ? null
                : new CspDirective(SCRIPT_SRC, String.join(" ", values));
    }

    private static CspDirective directive(String name, List<String> values) {
        return new CspDirective(name, String.join(" ", values));
    }
}
