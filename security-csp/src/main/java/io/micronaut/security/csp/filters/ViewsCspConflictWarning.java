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
import io.micronaut.core.util.StringUtils;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Warns at startup when the CSP filter of Micronaut Views is enabled as well, because both filters
 * write a CSP header and the {@code cspNonce} request attribute, so one overwrites the other's nonce.
 */
@Requires(property = ViewsCspConflictWarning.VIEWS_CSP_ENABLED, value = StringUtils.TRUE)
@Singleton
@Internal
final class ViewsCspConflictWarning implements ApplicationEventListener<StartupEvent> {
    /**
     * The property that enables the CSP filter of Micronaut Views.
     */
    static final String VIEWS_CSP_ENABLED = "micronaut.views.csp.enabled";
    private static final Logger LOG = LoggerFactory.getLogger(ViewsCspConflictWarning.class);

    @Override
    public void onApplicationEvent(StartupEvent event) {
        LOG.warn("Micronaut Views CSP and micronaut-security-csp are both active and both write the cspNonce request attribute "
            + "and a Content-Security-Policy header. Set {}=false.", VIEWS_CSP_ENABLED);
    }
}
