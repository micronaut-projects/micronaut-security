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

import io.micronaut.context.env.Environment;
import io.micronaut.context.event.ApplicationEventListener;
import io.micronaut.context.event.StartupEvent;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.csp.conf.reportto.ReportToConfigurationProperties;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Locale;
import java.util.Set;

import static io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties.PROPERTY_BASE_URI;
import static io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties.PROPERTY_CONNECT_SRC;
import static io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties.PROPERTY_DEFAULT_SRC;
import static io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties.PROPERTY_FENCED_FRAME_SRC;
import static io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties.PROPERTY_FONT_SRC;
import static io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties.PROPERTY_FORM_ACTION;
import static io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties.PROPERTY_FRAME_ANCESTORS;
import static io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties.PROPERTY_FRAME_SRC;
import static io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties.PROPERTY_IMG_SRC;
import static io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties.PROPERTY_MANIFEST_SRC;
import static io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties.PROPERTY_MEDIA_SRC;
import static io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties.PROPERTY_OBJECT_SRC;
import static io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties.PROPERTY_PREFETCH_SRC;
import static io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties.PROPERTY_REPORT_URI;
import static io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties.PROPERTY_REQUIRE_TRUSTED_TYPES_FOR;
import static io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties.PROPERTY_SCRIPT_SRC;
import static io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties.PROPERTY_STYLE_SRC;
import static io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties.PROPERTY_WORKER_SRC;

/**
 * Warns at startup about a directive {@code enabled} property whose value is not a boolean. Unlike
 * the module, filter and controller toggles, these properties are bound as booleans, and binding
 * converts any unknown value, such as the typo {@code ture}, to {@code false}: the directive is then
 * omitted, which for {@code base-uri}, {@code form-action} and {@code frame-ancestors} lifts its
 * restriction entirely.
 */
@Singleton
@Internal
final class DirectiveToggleValueWarning implements ApplicationEventListener<StartupEvent> {
    private static final Logger LOG = LoggerFactory.getLogger(DirectiveToggleValueWarning.class);
    private static final String ENABLED = ".enabled";
    private static final List<String> PREFIXES = List.of(PROPERTY_BASE_URI, PROPERTY_CONNECT_SRC, PROPERTY_DEFAULT_SRC,
        PROPERTY_FENCED_FRAME_SRC, PROPERTY_FONT_SRC, PROPERTY_FORM_ACTION, PROPERTY_FRAME_ANCESTORS, PROPERTY_FRAME_SRC,
        PROPERTY_IMG_SRC, PROPERTY_MANIFEST_SRC, PROPERTY_MEDIA_SRC, PROPERTY_OBJECT_SRC, PROPERTY_PREFETCH_SRC,
        PROPERTY_REPORT_URI, PROPERTY_REQUIRE_TRUSTED_TYPES_FOR, PROPERTY_SCRIPT_SRC, PROPERTY_STYLE_SRC, PROPERTY_WORKER_SRC,
        ReportToConfigurationProperties.PREFIX);
    /**
     * The spellings that boolean binding understands, compared without case.
     */
    private static final Set<String> BOOLEAN_VALUES = Set.of("true", "false", "yes", "no", "on", "off", "y", "n");

    private final Environment environment;

    /**
     * Creates the startup check.
     *
     * @param environment resolves the raw property values
     */
    DirectiveToggleValueWarning(Environment environment) {
        this.environment = environment;
    }

    @Override
    public void onApplicationEvent(StartupEvent event) {
        for (String prefix : PREFIXES) {
            String property = prefix + ENABLED;
            environment.getProperty(property, String.class)
                .filter(value -> !BOOLEAN_VALUES.contains(value.trim().toLowerCase(Locale.ROOT)))
                .ifPresent(value -> LOG.warn("{} is \"{}\", which is not a boolean; it binds as false, so the directive is not written. "
                    + "Use true or false.", property, value));
        }
    }
}
