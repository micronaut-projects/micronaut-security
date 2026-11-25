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

import io.micronaut.context.annotation.Context;
import io.micronaut.context.env.Environment;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.csp.conf.reportto.ReportToConfigurationProperties;

import java.util.List;
import java.util.Locale;
import java.util.Set;

import static io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties.PREFIX;
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
 * Rejects a policy setting whose value is not a boolean. Directive settings are bound as booleans,
 * and binding converts any unknown value, such as {@code 1} or the typo {@code ture}, to
 * {@code false}: {@code frame-ancestors.enabled=1} would remove the directive, and
 * {@code script-src.nonce=1} would leave {@code 'unsafe-inline'} active.
 *
 * <p>The bean is created at startup, where an invalid value fails application startup, and the
 * generator's refresh listener runs the same check, so that a refresh with such a value is rejected
 * and the previous policy kept.</p>
 */
@Context
@Internal
final class BooleanPropertiesCheck {
    /**
     * The spellings that boolean binding understands, compared without case.
     */
    static final Set<String> BOOLEAN_VALUES = Set.of("true", "false", "yes", "no", "on", "off", "y", "n");
    private static final List<String> PREFIXES = List.of(PROPERTY_BASE_URI, PROPERTY_CONNECT_SRC, PROPERTY_DEFAULT_SRC,
        PROPERTY_FENCED_FRAME_SRC, PROPERTY_FONT_SRC, PROPERTY_FORM_ACTION, PROPERTY_FRAME_ANCESTORS, PROPERTY_FRAME_SRC,
        PROPERTY_IMG_SRC, PROPERTY_MANIFEST_SRC, PROPERTY_MEDIA_SRC, PROPERTY_OBJECT_SRC, PROPERTY_PREFETCH_SRC,
        PROPERTY_SCRIPT_SRC, PROPERTY_STYLE_SRC, PROPERTY_WORKER_SRC);
    /**
     * The boolean settings of a source-list directive.
     */
    private static final List<String> SOURCE_LIST_KEYS = List.of("enabled", "none", "self", "nonce", "unsafe-inline", "unsafe-eval",
        "strict-dynamic", "unsafe-hashes", "report-sample", "wasm-unsafe-eval", "trusted-types-eval", "report-sha256", "report-sha384",
        "report-sha512", "unsafe-webtransport-hashes", "http", "https", "data", "blob", "filesystem", "mediastream", "ws", "wss");
    /**
     * The other boolean policy settings.
     */
    private static final List<String> OTHER_PROPERTIES = List.of(PREFIX + ".report-only", PROPERTY_REPORT_URI + ".enabled",
        PROPERTY_REQUIRE_TRUSTED_TYPES_FOR + ".enabled", ReportToConfigurationProperties.PREFIX + ".enabled");

    private final Environment environment;

    /**
     * Creates the check and runs it.
     *
     * @param environment resolves the raw property values
     * @throws ConfigurationException if a policy setting is not a boolean
     */
    BooleanPropertiesCheck(Environment environment) {
        this.environment = environment;
        check();
    }

    /**
     * Checks the current configuration.
     *
     * @throws ConfigurationException if a policy setting is not a boolean
     */
    void check() {
        for (String prefix : PREFIXES) {
            for (String key : SOURCE_LIST_KEYS) {
                check(prefix + "." + key);
            }
        }
        for (String property : OTHER_PROPERTIES) {
            check(property);
        }
    }

    private void check(String property) {
        environment.getProperty(property, String.class)
            .filter(value -> !BOOLEAN_VALUES.contains(value.trim().toLowerCase(Locale.ROOT)))
            .ifPresent(value -> {
                throw new ConfigurationException(property + " is \"" + ContentSecurityPolicyUtils.printable(value)
                    + "\", which is not a boolean and would bind as false. Use true or false.");
            });
    }
}
