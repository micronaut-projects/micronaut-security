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

import io.micronaut.context.annotation.Requires;
import io.micronaut.context.event.ApplicationEventListener;
import io.micronaut.context.event.StartupEvent;
import io.micronaut.core.annotation.Internal;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Warns at startup when the CSP module is enabled but cannot write the header, because the
 * {@code ResponseHeaderPopulator} API it relies on is missing from the HTTP server on the classpath.
 */
@Requires(missingClasses = ContentSecurityPolicyHeaderUnavailableWarning.RESPONSE_HEADER_POPULATOR)
@Singleton
@Internal
final class ContentSecurityPolicyHeaderUnavailableWarning implements ApplicationEventListener<StartupEvent> {
    static final String RESPONSE_HEADER_POPULATOR = "io.micronaut.http.server.filter.ResponseHeaderPopulator";
    private static final Logger LOG = LoggerFactory.getLogger(ContentSecurityPolicyHeaderUnavailableWarning.class);

    @Override
    public void onApplicationEvent(StartupEvent event) {
        LOG.warn("micronaut-security-csp is enabled but cannot write the Content-Security-Policy header: it needs {} from "
            + "micronaut-http-server 5.2 or later. No CSP header is sent.", RESPONSE_HEADER_POPULATOR);
    }
}
