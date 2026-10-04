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
package io.micronaut.security.csp.filters;

import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.Toggleable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.RequestFilter;
import io.micronaut.http.annotation.ServerFilter;
import io.micronaut.security.csp.conf.NonceConfiguration;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;

import java.util.List;

/**
 * Generates the Content Security Policy nonce for a request when any enabled directive, such as
 * {@code script-src} or {@code style-src}, uses nonces. Every such directive shares the same nonce.
 *
 * <p>The CSP response header is written by {@link ContentSecurityPolicyResponseHeaderPopulator}.</p>
 *
 * @author Sergio del Amo
 */
@Internal
@ServerFilter("${" + ContentSecurityPolicyFilterConfigurationProperties.PREFIX + ".pattern:" + ServerFilter.MATCH_ALL_PATTERN + "}")
final class ContentSecurityPolicyFilter {
    private final List<NonceConfiguration> nonceConfigurations;
    private final ContentSecurityPolicyNonceGenerator cspNonceGenerator;

    /**
     * Creates the server filter that generates request nonces.
     *
     * @param nonceConfigurations directive configurations that support nonces
     * @param cspNonceGenerator generates per-response CSP nonces
     */
    ContentSecurityPolicyFilter(List<NonceConfiguration> nonceConfigurations,
                                ContentSecurityPolicyNonceGenerator cspNonceGenerator) {
        this.nonceConfigurations = nonceConfigurations;
        this.cspNonceGenerator = cspNonceGenerator;
    }

    /**
     * Generates and stores the nonce before view rendering and response policy generation when
     * nonce support is enabled for any directive.
     *
     * @param request the current request
     */
    @RequestFilter
    void generateNonce(HttpRequest<?> request) {
        if (nonceConfigurations.stream().anyMatch(ContentSecurityPolicyFilter::isNonceEnabled)) {
            request.setAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, cspNonceGenerator.generateNonce(request));
        }
    }

    private static boolean isNonceEnabled(NonceConfiguration configuration) {
        return configuration.isNonce() && (!(configuration instanceof Toggleable toggleable) || toggleable.isEnabled());
    }
}
