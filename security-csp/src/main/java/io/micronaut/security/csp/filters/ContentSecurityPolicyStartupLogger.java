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

import io.micronaut.context.event.ApplicationEventListener;
import io.micronaut.context.event.StartupEvent;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.csp.ContentSecurityPolicy;
import io.micronaut.security.csp.ContentSecurityPolicyGenerator;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfiguration;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Logs once at startup which CSP header the module writes and where, because adding the module
 * applies a deny-by-default policy to every matching response.
 */
@Singleton
@Internal
final class ContentSecurityPolicyStartupLogger implements ApplicationEventListener<StartupEvent> {
    private static final Logger LOG = LoggerFactory.getLogger(ContentSecurityPolicyStartupLogger.class);
    private final ContentSecurityPolicyConfiguration cspConfiguration;
    private final ContentSecurityPolicyFilterConfiguration filterConfiguration;

    /**
     * Creates the startup logger.
     *
     * <p>The generator is injected so that it is created at startup: invalid policy configuration
     * then fails application startup instead of every response.</p>
     *
     * @param cspConfiguration the root CSP configuration
     * @param filterConfiguration the configuration of the requests that receive the header
     * @param cspGenerator the policy generator, created eagerly to validate its configuration
     */
    ContentSecurityPolicyStartupLogger(ContentSecurityPolicyConfiguration cspConfiguration,
                                       ContentSecurityPolicyFilterConfiguration filterConfiguration,
                                       ContentSecurityPolicyGenerator cspGenerator) {
        this.cspConfiguration = cspConfiguration;
        this.filterConfiguration = filterConfiguration;
    }

    @Override
    public void onApplicationEvent(StartupEvent event) {
        if (cspConfiguration.isReportOnly()) {
            LOG.info("Writing the {} header on requests matching {}; violations are reported, not blocked. "
                + "Remove micronaut.security.csp.report-only to enforce the policy.",
                ContentSecurityPolicy.CONTENT_SECURITY_POLICY_REPORT_ONLY, filterConfiguration.getPattern());
        } else {
            LOG.info("Enforcing the {} header on requests matching {}; directives default to 'none'. "
                + "Set micronaut.security.csp.report-only=true to evaluate the policy first, or narrow micronaut.security.csp.filter.pattern.",
                ContentSecurityPolicy.CONTENT_SECURITY_POLICY, filterConfiguration.getPattern());
        }
    }
}
