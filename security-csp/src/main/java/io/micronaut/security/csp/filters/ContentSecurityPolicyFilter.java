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
import io.micronaut.core.order.Ordered;
import io.micronaut.core.util.Toggleable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.RequestFilter;
import io.micronaut.http.annotation.ServerFilter;
import io.micronaut.http.filter.ServerFilterPhase;
import io.micronaut.security.csp.ContentSecurityPolicyGenerator;
import io.micronaut.security.csp.DefaultContentSecurityPolicyGenerator;
import io.micronaut.security.csp.conf.NonceConfiguration;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;

import java.util.List;
import java.util.function.BooleanSupplier;

/**
 * Selects the requests that receive the Content Security Policy and generates their nonce.
 *
 * <p>Micronaut Core matches {@value ContentSecurityPolicyFilterConfigurationProperties#PREFIX}{@code .pattern}
 * against the request, so this filter marks every request it runs on with
 * {@link #MATCHED_ATTRIBUTE}, and {@link ContentSecurityPolicyResponseHeaderPopulator} writes the
 * header exactly for the marked requests. The pattern is therefore matched once, the way the server
 * matches filter patterns, including comma-separated patterns and the server context path.</p>
 *
 * <p>When an enabled directive, such as {@code script-src} or {@code style-src}, uses nonces, the
 * filter also stores one nonce for the request, which every such directive shares. Whether a
 * directive uses nonces is decided for each request, from the policy of the default generator, so
 * a configuration refresh that enables nonces takes effect without a restart and a refresh that the
 * generator rejects changes nothing. With another generator, the directive configuration decides.</p>
 *
 * <p>The filter runs before the filters of the other server filter phases, so a response that one of
 * them returns early, such as a security rejection, still carries the policy and the nonce.</p>
 *
 * @author Sergio del Amo
 */
@Internal
@ServerFilter("${" + ContentSecurityPolicyFilterConfigurationProperties.PREFIX + ".pattern:" + ServerFilter.MATCH_ALL_PATTERN + "}")
final class ContentSecurityPolicyFilter implements Ordered {
    /**
     * The request attribute that marks a request matched by the filter pattern.
     */
    static final String MATCHED_ATTRIBUTE = "io.micronaut.security.csp.filters.matched";

    private final ContentSecurityPolicyNonceGenerator cspNonceGenerator;
    private final BooleanSupplier usesNonce;

    /**
     * Creates the server filter.
     *
     * @param cspNonceGenerator generates per-response CSP nonces
     * @param cspGenerator the policy generator
     * @param nonceConfigurations the configuration of every directive that can use nonces
     */
    ContentSecurityPolicyFilter(ContentSecurityPolicyNonceGenerator cspNonceGenerator,
                                ContentSecurityPolicyGenerator cspGenerator,
                                List<NonceConfiguration> nonceConfigurations) {
        this.cspNonceGenerator = cspNonceGenerator;
        this.usesNonce = cspGenerator instanceof DefaultContentSecurityPolicyGenerator defaultGenerator
            ? defaultGenerator::usesNonce
            : () -> usesNonce(nonceConfigurations);
    }

    /**
     * Marks the request and, when a directive uses nonces, stores its nonce before view rendering
     * and response policy generation.
     *
     * @param request the current request
     */
    @RequestFilter
    void filterRequest(HttpRequest<?> request) {
        request.setAttribute(MATCHED_ATTRIBUTE, Boolean.TRUE);
        if (usesNonce.getAsBoolean()) {
            request.setAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, cspNonceGenerator.generateNonce(request));
        }
    }

    @Override
    public int getOrder() {
        return ServerFilterPhase.FIRST.before();
    }

    private static boolean usesNonce(List<NonceConfiguration> nonceConfigurations) {
        for (NonceConfiguration configuration : nonceConfigurations) {
            if (configuration.isNonce() && (!(configuration instanceof Toggleable toggleable) || toggleable.isEnabled())) {
                return true;
            }
        }
        return false;
    }
}
